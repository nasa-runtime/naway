//! 相同文件协议资源域跨快照共用并发事实，另设进程总量保护。
use anyhow::{ensure, Result};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock, Weak,
    },
};

static GLOBAL: AtomicUsize = AtomicUsize::new(0);
pub(super) struct Quota(AtomicUsize);
pub(super) struct Permit(Arc<Quota>);

impl Quota {
    /// 业务作用：复用相同资源域的活动计数，热更新不得清零仍在处理的请求。
    ///
    /// 参数说明：
    /// - `identity`：由固定后端、挂载点或本地 canonical root 生成的稳定摘要。
    ///
    /// 返回：最多 1024 个活动资源域之一；目录容量不足时拒绝候选。
    pub fn shared(identity: String) -> Result<Arc<Self>> {
        static REGISTRY: OnceLock<parking_lot::Mutex<BTreeMap<String, Weak<Quota>>>> =
            OnceLock::new();
        let mut entries = REGISTRY.get_or_init(Default::default).lock();
        entries.retain(|_, entry| entry.strong_count() > 0);
        if let Some(quota) = entries.get(&identity).and_then(Weak::upgrade) {
            return Ok(quota);
        }
        ensure!(
            entries.len() < 1024,
            "WebDAV admission domain capacity reached"
        );
        let quota = Arc::new(Self(AtomicUsize::new(0)));
        entries.insert(identity, Arc::downgrade(&quota));
        Ok(quota)
    }
    /// 业务作用：同时预留本代资源域上限和进程 128 个操作硬上限，不排队积压文件请求。
    ///
    /// 参数说明：
    /// - `limit`：当前快照的资源域并发上限，降低上限后等待旧操作自然结束。
    ///
    /// 返回：两个计数都成功时取得凭证；任一满额不留下部分预留。
    pub fn acquire(self: &Arc<Self>, limit: usize) -> Option<Permit> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()?;
        if GLOBAL
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < 128).then_some(active + 1)
            })
            .is_err()
        {
            self.0.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Permit(self.clone()))
    }
}
impl Drop for Permit {
    /// 业务作用：完整响应结束或取消时归还资源域和进程容量，不受配置代际影响。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：恰好释放一次已预留的两个计数。
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::AcqRel);
        GLOBAL.fetch_sub(1, Ordering::AcqRel);
    }
}
