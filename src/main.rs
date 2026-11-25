//! Naway 可执行入口。

extern crate naway as gateway;
mod app;

// Linux 转发路径使用进程分配器，减少短命协议对象对共享分配器的竞争。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// 业务作用：建立异步运行时并执行网关进程生命周期。
///
/// 参数说明: 无。
///
/// 返回：正常停机返回成功；启动或运行失败返回非零退出状态。
fn main() -> anyhow::Result<()> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    #[cfg(debug_assertions)]
    {
        // 调试构建保留未内联的模型转发与协议栈帧。为工作线程预留栈，避免协议叠加时终止整个网关。
        const MIN_WORKER_STACK_BYTES: usize = 4 * 1024 * 1024;
        let requested_stack = std::env::var("RUST_MIN_STACK")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(MIN_WORKER_STACK_BYTES);
        runtime.thread_stack_size(requested_stack.max(MIN_WORKER_STACK_BYTES));
    }
    runtime.build()?.block_on(app::run())
}
