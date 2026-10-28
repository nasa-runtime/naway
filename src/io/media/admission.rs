//! 跨快照复用静态根的活动计数；进程同时限制任务数与保守内存预留。
use anyhow::{ensure, Result};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock, Weak,
    },
};
static GLOBAL: parking_lot::Mutex<(usize, usize)> = parking_lot::Mutex::new((0, 0));
pub(super) struct Quota(AtomicUsize);
pub(super) struct Permit {
    quota: Arc<Quota>,
    bytes: usize,
}
impl Quota {
    /// 业务作用：相同真实根共享解析准入事实，热更新不能清空旧响应仍持有的资源。
    ///
    /// 参数说明：
    /// - `key`：规范静态根的稳定摘要。
    ///
    /// 返回：有界目录中的共享计数器；最多 1024 个活动根。
    pub fn shared(key: String) -> Result<Arc<Self>> {
        static ENTRIES: OnceLock<parking_lot::Mutex<BTreeMap<String, Weak<Quota>>>> =
            OnceLock::new();
        let mut entries = ENTRIES.get_or_init(Default::default).lock();
        entries.retain(|_, value| value.strong_count() > 0);
        if let Some(value) = entries.get(&key).and_then(Weak::upgrade) {
            return Ok(value);
        }
        ensure!(
            entries.len() < 1024,
            "media admission directory capacity reached"
        );
        let value = Arc::new(Self(AtomicUsize::new(0)));
        entries.insert(key, Arc::downgrade(&value));
        Ok(value)
    }
    /// 业务作用：在阻塞任务及元数据分配前同时预留根并发、全进程八任务及 256MiB 工作集。
    ///
    /// 参数说明：
    /// - `limit`：当前路由允许的根并发上限。
    /// - `bytes`：配置计算的保守工作集。
    ///
    /// 返回：全部准入成功的凭证；满额立即拒绝，不建立等待队列。
    pub fn acquire(self: &Arc<Self>, limit: usize, bytes: usize) -> Option<Permit> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        let mut global = GLOBAL.lock();
        if global.0 >= 8 || bytes > (256 << 20) - global.1 {
            self.0.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        global.0 += 1;
        global.1 += bytes;
        Some(Permit {
            quota: self.clone(),
            bytes,
        })
    }
}
impl Drop for Permit {
    /// 业务作用：解析、响应和阻塞任务全部结束后归还工作集，取消等待不能提前释放任务的容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅归还本凭证已经取得的资源。
    fn drop(&mut self) {
        let mut global = GLOBAL.lock();
        global.0 -= 1;
        global.1 -= self.bytes;
        self.quota.0.fetch_sub(1, Ordering::AcqRel);
    }
}
