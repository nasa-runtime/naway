//! 指令、分配与线程 CPU 预算由同一个调用状态维护，不向客体暴露时钟。
use super::Failure;
use crate::config::scripts::ScriptCfg;
use std::{cell::Cell, rc::Rc};

pub(super) struct Guard {
    pub wall: nabudget::RequestBudget,
    reason: Cell<Option<Failure>>,
    instructions: Cell<u64>,
    allocations: Cell<u64>,
    cpu_start: u64,
    max_cpu_ns: u64,
    max_instructions: u64,
    max_allocations: u64,
}
impl Guard {
    /// 业务作用：在执行线程记录调用起点，冻结所有客体执行预算。
    ///
    /// 参数说明：
    /// - `cfg`：构建期通过校验的预算配置。
    /// - `wall`：包含排队等待时间的共享取消与期限。
    ///
    /// 返回：线程局部计数器；无法取得 CPU 时钟时失败关闭。
    pub fn new(cfg: &ScriptCfg, wall: nabudget::RequestBudget) -> Result<Rc<Self>, Failure> {
        Ok(Rc::new(Self {
            wall,
            reason: Cell::new(None),
            instructions: Cell::new(0),
            allocations: Cell::new(0),
            cpu_start: cpu_time()?,
            max_cpu_ns: cfg.max_cpu_ms * 1_000_000,
            max_instructions: cfg.max_instructions,
            max_allocations: cfg.max_allocations,
        }))
    }
    /// 业务作用：保留首次拒绝原因，后续解释器清理错误不能掩盖本地硬门。
    ///
    /// 参数说明：
    /// - `reason`：已触发的硬门。
    ///
    /// 返回：首次拒绝原因并令后续检查继续拒绝。
    pub fn deny(&self, reason: Failure) -> Failure {
        let first = self.reason.get().unwrap_or(reason);
        self.reason.set(Some(first));
        first
    }
    /// 业务作用：将解释器异常映射为固定低敏原因，不将脚本输入或源码带出沙箱。
    ///
    /// 参数说明：
    /// - `error`：解释器错误，只识别内存类别。
    ///
    /// 返回：预算原因优先，否则为脚本拒绝。
    pub fn classify(&self, error: mlua::Error) -> Failure {
        self.reason
            .get()
            .unwrap_or(if matches!(error, mlua::Error::MemoryError(_)) {
                Failure::Memory
            } else {
                Failure::Script
            })
    }
    /// 业务作用：在执行边界复验取消、绝对期限和实际线程 CPU，过期输出不得发布。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍有执行权时成功，否则固定首次拒绝原因。
    pub fn check(&self) -> Result<(), Failure> {
        if let Some(reason) = self.reason.get() {
            return Err(reason);
        }
        if let Err(error) = self.wall.check() {
            return Err(self.deny(match error {
                nabudget::BudgetError::Cancelled => Failure::Cancelled,
                nabudget::BudgetError::DeadlineExceeded => Failure::Deadline,
            }));
        }
        if cpu_time()?.saturating_sub(self.cpu_start) >= self.max_cpu_ns {
            return Err(self.deny(Failure::Cpu));
        }
        Ok(())
    }
    /// 业务作用：以固定短周期中断 Lua 字节码，死循环不能占满执行线程。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：指令与时钟门均通过才继续运行。
    pub fn tick(&self) -> Result<(), Failure> {
        let next = self.instructions.get().saturating_add(100);
        self.instructions.set(next);
        if next >= self.max_instructions {
            return Err(self.deny(Failure::Instructions));
        }
        self.check()
    }
    /// 业务作用：限制累计新分配和扩容次数，反复释放内存不能绕过资源预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：允许此次扩容时成功；耗尽后保持拒绝，但不阻止释放和缩容。
    pub fn allocate(&self) -> Result<(), Failure> {
        let next = self.allocations.get().saturating_add(1);
        self.allocations.set(next);
        if next > self.max_allocations {
            return Err(self.deny(Failure::Allocations));
        }
        self.check()
    }
}
/// 业务作用：只为宿主预算读取线程消耗，客体没有访问非确定时钟的接口。
///
/// 参数说明: 无。
///
/// 返回：当前线程累计 CPU 纳秒；平台不支持或调用失败时拒绝执行。
fn cpu_time() -> Result<u64, Failure> {
    #[cfg(unix)]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // 指针指向有效栈对象；线程时钟不执行外部业务操作，失败时不回退无界运行。
        if unsafe {
            libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time)
        } != 0 {
            return Err(Failure::Dependency);
        }
        Ok((time.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(time.tv_nsec as u64))
    }
    #[cfg(not(unix))]
    {
        Err(Failure::Dependency)
    }
}
