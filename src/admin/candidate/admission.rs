//! 构建许可跟随真实阻塞任务，不随HTTP等待者提前释放。

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 一个管理实例允许同时存在的候选工作单元。
pub(in crate::admin) struct Admission {
    permits: Arc<Semaphore>,
}

/// 已受理任务独占的容量，排队、执行与清理共用同一生命周期。
pub(in crate::admin) struct Permit {
    _permit: OwnedSemaphorePermit,
    admission: Arc<Semaphore>,
}

impl Admission {
    /// 业务作用：为管理实例固定两个候选构建槽，热更不重置已有工作单元的容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未启动任务的共享许可域，不创建线程或等待队列。
    pub(in crate::admin) fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(2)),
        }
    }

    /// 业务作用：在复制原文和创建工作区之前受理任务，容量不足时立即背压。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：独占工作许可；已有两个未结束任务时返回忙碌，不排队等待。
    pub(in crate::admin) fn acquire(&self) -> Result<Permit, super::BuildError> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| super::BuildError::Busy)?;
        Ok(Permit {
            _permit: permit,
            admission: self.permits.clone(),
        })
    }
}

impl Permit {
    /// 业务作用：清理证据不足时关闭本实例后续候选受理，防止持续失败积累未清理原文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：现有任务继续完成自己的清理，新受理立即失败；只有新进程建立新的容量域。
    pub(super) fn close_admission(&self) {
        self.admission.close();
    }

    /// 业务作用：将许可转交实际阻塞工作单元，取消等待不能重新开放尚未释放的资源。
    ///
    /// 参数说明：
    /// - `work`：拥有原文和临时文件清理职责的完整构建工作。
    ///
    /// 返回：可等待的任务句柄；许可仅在工作返回或展开退出后释放，取消未执行任务也不遗留资源。
    pub(in crate::admin) fn spawn<T, F>(self, work: F) -> tokio::task::JoinHandle<T>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> T + Send + 'static,
    {
        // 许可必须由闭包实际持有；JoinHandle被丢弃不会取消已经运行的阻塞任务。
        tokio::task::spawn_blocking(move || {
            let permit = self;
            work(&permit)
        })
    }
}
