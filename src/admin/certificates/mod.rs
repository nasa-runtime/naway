//! 集群证书目录来源于实际安装事实，不以磁盘材料或配置声明代替在线身份。

pub(super) mod local;
mod model;
pub(super) mod read;

#[cfg(any(test, feature = "admin-grpc"))]
pub(in crate::admin) use model::digest;
#[cfg(feature = "admin-grpc")]
pub(in crate::admin) use model::valid_directory;
#[cfg(feature = "admin-grpc")]
pub(in crate::admin) use model::MAX_ENTRIES;
pub(in crate::admin) use model::{Directory, Entry, MAX_BYTES};

use crate::config::GatewaySnapshot;
use crate::tls::installed::{InstalledCertificates, InstalledSnapshot};
use std::sync::{Arc, Weak};

struct Cached {
    owner: Weak<GatewaySnapshot>,
    installed: InstalledSnapshot,
    directory: Arc<Directory>,
}

pub(in crate::admin) struct Runtime {
    local: parking_lot::Mutex<Option<Cached>>,
    installs: Arc<tokio::sync::Semaphore>,
}

impl Default for Runtime {
    /// 业务作用：为证书观察与材料写入分别建立独立容量，少量写入等待不能占满阻塞线程池。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空观察缓存与两个实际安装任务许可，不读取材料或创建背景任务。
    fn default() -> Self {
        Self {
            local: parking_lot::Mutex::new(None),
            installs: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}

impl Runtime {
    /// 业务作用：按配置与实际安装材料双重身份共享证书目录，热换无需依赖配置版本改变。
    ///
    /// 参数说明：
    /// - `snapshot`：当前已发布的配置与归属权威。
    /// - `installed`：listener 唯一安装事实注册表。
    /// - `serves_data`：进程部署形态是否承载业务监听器，启动后固定。
    ///
    /// 返回：所有管理目标共享的有界目录；配置、换材或动态失权改变时才重新收集。
    pub(in crate::admin) fn local(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        installed: &InstalledCertificates,
        serves_data: bool,
    ) -> Arc<Directory> {
        let mut local = self.local.lock();
        let observed = installed.snapshot();
        if let Some(cached) = local.as_ref() {
            if cached
                .owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, snapshot))
                && cached.installed.same_generation(&observed)
            {
                return cached.directory.clone();
            }
        }
        let directory = Arc::new(model::collect(snapshot, &observed, serves_data));
        *local = Some(Cached {
            owner: Arc::downgrade(snapshot),
            installed: observed,
            directory: directory.clone(),
        });
        directory
    }
}
