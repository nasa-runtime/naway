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
/// 命令行与环境配置由启动模块读取。
///
/// 返回：正常停机返回成功；启动或运行失败返回非零退出状态。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
