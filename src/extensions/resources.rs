//! 进程内客体共用 VM 工作集和执行线程容量，语言切换不能建立配额旁路。
use std::{
    cell::Cell,
    fmt,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};
static RESIDENT: parking_lot::Mutex<(usize, usize)> = parking_lot::Mutex::new((0, 0));
static RUNNING: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static DEPTH: Cell<usize> = const {
        Cell::new(0)
    };
}
#[derive(Debug)]
pub(crate) struct Denied;
impl fmt::Display for Denied {
    /// 业务作用：提供固定资源拒绝原因，不暴露其它请求的占用明细。
    ///
    /// 参数说明：
    /// - `out`：错误文本目标。
    ///
    /// 返回：不能被扩展 fail-open 放行的低敏资源错误。
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("shared extension resource capacity reached")
    }
}
impl std::error::Error for Denied {}
pub(crate) struct Lease {
    bytes: usize,
}
impl Lease {
    /// 业务作用：创建客体之前预留全部运行工作集，暂停和流式实例继续持有凭证。
    ///
    /// 参数说明：
    /// - `bytes`：执行器按客体与宿主副本上限计算的保守字节数。
    ///
    /// 返回：64 实例及 512MiB 总量内的凭证；满额立即拒绝，不建立等待队列。
    pub fn acquire(bytes: usize) -> Result<Self, Denied> {
        let mut state = RESIDENT.lock();
        if state.0 >= 64 || bytes > (512 << 20) - state.1 {
            return Err(Denied);
        }
        state.0 += 1;
        state.1 += bytes;
        Ok(Self {
            bytes,
        })
    }
}
impl Drop for Lease {
    /// 业务作用：实例及阻塞任务真正结束后归还资源，取消等待不能提前借出相同容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：恰好归还本实例预留的数量与字节。
    fn drop(&mut self) {
        let mut state = RESIDENT.lock();
        state.0 -= 1;
        state.1 -= self.bytes;
    }
}
pub(crate) struct Worker {
    charged: bool,
    local: PhantomData<Rc<()>>,
}
impl Worker {
    /// 业务作用：限制同时执行客体代码的任务，所有语言共享八个席位。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：执行席位凭证；满额立即拒绝，不把压力排进无界工作队列。
    pub fn acquire() -> Result<Self, Denied> {
        DEPTH.with(|depth| {
            let nested = depth.get() > 0;
            if !nested {
                RUNNING
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < 8).then_some(active + 1)
                    })
                    .map_err(|_| Denied)?;
            }
            depth.set(depth.get() + 1);
            Ok(Self {
                charged: !nested,
                local: PhantomData,
            })
        })
    }
}
impl Drop for Worker {
    /// 业务作用：同步客体回调结束后释放执行席位，暂停状态继续受实例预算约束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还当前任务的唯一执行名额。
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get() - 1));
        if self.charged {
            RUNNING.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
/// 业务作用：保持共享资源拒绝的失败关闭语义，额外业务上下文不能将其转成 fail-open。
///
/// 参数说明：
/// - `error`：执行错误及上下文链。
///
/// 返回：错误链包含本地共享资源拒绝时为 true。
pub(crate) fn denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<Denied>())
}
