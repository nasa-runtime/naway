//! 命令行、配置定位与进程重载信号。

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gateway::admin;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "naway")]
#[command(about = "Naway high-performance Rust traffic + business gateway")]
pub(super) struct Args {
    /// 运行形态；省略时兼容旧命令，按 `all-in-one` 启动。
    #[command(subcommand)]
    pub(super) command: Option<RunMode>,
    /// 主配置文件路径（默认 `/data/naway/naway.yml`，或环境变量 `NAWAY_CONFIG`；兼容 `GW_CONFIG`）。
    #[arg(long)]
    pub(super) config: Option<String>,
    /// 向运行中的进程发信号:`reload` = SIGHUP 热更(nginx `-s reload` 风格)。
    #[arg(short = 's', long = "signal")]
    pub(super) signal: Option<String>,
    /// 显式初始化持久管理操作数据库后退出，不开放服务监听。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_migrate: bool,
    /// 只读查看共享容量及比较交换令牌后退出，不登记或调整集群。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_capacity_status: bool,
    /// 按原 revision:sha256 令牌将共享容量调整为配置中的目标预算后退出。
    #[arg(
        long,
        group = "operations_maintenance",
        conflicts_with = "signal",
        value_name = "REVISION:SHA256"
    )]
    pub(super) admin_operations_capacity_expected: Option<String>,
    /// 只读查看持久执行存储所属集群后退出，不登记集群或执行目标动作。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_execution_status: bool,
    /// 将持久执行存储永久绑定到配置集群后退出，不允许已有其它集群。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_execution_bind: bool,
    /// 显式初始化已绑定集群的 NASA 工作流结构后退出，不开启节点执行。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_workflow_migrate: bool,
    /// 只读复验工作流结构与在途定义后退出，不创建后台任务。
    #[arg(long, group = "operations_maintenance", conflicts_with = "signal")]
    pub(super) admin_operations_workflow_status: bool,
    /// 固定节点journal目录；启用时先验证存储owner，再自动补齐配置或开放资源。
    #[arg(long, value_name = "DIR", conflicts_with_all = ["signal", "operations_maintenance"])]
    pub(super) node_journal: Option<PathBuf>,
    /// 在已创建的私有空目录显式绑定节点身份后退出，不开启动作执行。
    #[arg(long, group = "journal_maintenance", requires_all = ["node_journal", "node_journal_node", "node_journal_cluster"])]
    pub(super) node_journal_init: bool,
    /// 只读查看永久节点身份和owner占用后退出。
    #[arg(long, group = "journal_maintenance", requires = "node_journal")]
    pub(super) node_journal_status: bool,
    /// 在已绑定身份的目录显式初始化受理代际存储后退出，不开启动作执行。
    #[arg(long, group = "journal_maintenance", requires = "node_journal")]
    pub(super) node_journal_storage_init: bool,
    /// 离线按原revision:sha256令牌关闭当前受理代际并开启下一代后退出。
    #[arg(
        long,
        group = "journal_maintenance",
        requires = "node_journal",
        value_name = "REVISION:SHA256"
    )]
    pub(super) node_journal_close_epoch: Option<String>,
    /// 离线按完整状态令牌将未决本地发布选择为原基线方向，恢复后退出并等待正常启动确认。
    #[arg(
        long,
        group = "journal_maintenance",
        requires = "node_journal",
        value_name = "REVISION:SHA256"
    )]
    pub(super) node_journal_rollback_local: Option<String>,
    /// 显式初始化时的永久管理节点标识。
    #[arg(long, requires = "node_journal_init")]
    pub(super) node_journal_node: Option<String>,
    /// 显式初始化时的永久发行集群标识。
    #[arg(long, requires = "node_journal_init")]
    pub(super) node_journal_cluster: Option<String>,
}

/// 单一二进制的平面部署模式；生产可把数据面与控制面拆成不同权限/生命周期的进程。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub(super) enum RunMode {
    /// 只运行数据面与最小观测/节点运维入口。
    Data,
    /// 运行本地 service-mesh sidecar 数据面；业务 listener 强制只绑定 loopback。
    Sidecar,
    /// 只运行完整管理面；不绑定 public HTTP/TLS/L4 listener。
    Admin,
    /// 同一进程同时运行数据面与完整管理面，兼容旧启动方式。
    AllInOne,
}

impl RunMode {
    /// 业务作用：判断当前进程是否需要创建业务数据面资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`data`、`sidecar`、`all-in-one` 返回 true，纯 `admin` 返回 false。
    pub(super) fn runs_data(self) -> bool {
        matches!(self, Self::Data | Self::Sidecar | Self::AllInOne)
    }

    /// 业务作用：把 CLI 部署模式映射到管理 API 权限边界，避免 admin 模块依赖 binary 类型。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：sidecar 与 data 均只开放数据面最小运维权限，其余模式保持原管理边界。
    pub(super) fn admin_plane_mode(self) -> admin::AdminPlaneMode {
        match self {
            Self::Data => admin::AdminPlaneMode::Data,
            Self::Sidecar => admin::AdminPlaneMode::Sidecar,
            Self::Admin => admin::AdminPlaneMode::Admin,
            Self::AllInOne => admin::AdminPlaneMode::AllInOne,
        }
    }

    /// 业务作用：标记是否启用 sidecar 专属 listener 暴露门禁。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅 `sidecar` 模式返回 true。
    pub(super) fn is_sidecar(self) -> bool {
        self == Self::Sidecar
    }
}

/// Naway 外部配置固定目录(可 Docker 挂载)。`GW_*` 仅保留为旧迁移变量，不再提供旧品牌默认入口。
pub(super) const DEFAULT_CONFIG_DIR: &str = "/data/naway";
pub(super) const DEFAULT_CONFIG_FILE: &str = "naway.yml";
/// 业务作用：解析 Naway 主配置路径，并保持显式参数、品牌环境变量与通用兼容变量的确定优先级。
///
/// 参数说明：
/// - `args`：提供命令行显式配置路径。
///
/// 返回：依次选择 `--config`、`NAWAY_CONFIG`、`GW_CONFIG`、`NAWAY_CONFIG_DIR`、
/// `GW_CONFIG_DIR` 或默认目录下的 `naway.yml`；接口守卫相对最终主配置目录解析。
pub(super) fn config_path(args: &Args) -> PathBuf {
    if let Some(c) = &args.config {
        return c.into();
    }
    if let Ok(c) = std::env::var("NAWAY_CONFIG") {
        return c.into();
    }
    if let Ok(c) = std::env::var("GW_CONFIG") {
        return c.into();
    }
    if let Ok(dir) = std::env::var("NAWAY_CONFIG_DIR") {
        return PathBuf::from(dir).join(DEFAULT_CONFIG_FILE);
    }
    if let Ok(dir) = std::env::var("GW_CONFIG_DIR") {
        let dir = PathBuf::from(dir);
        let branded = dir.join(DEFAULT_CONFIG_FILE);
        return branded;
    }
    PathBuf::from(DEFAULT_CONFIG_DIR).join(DEFAULT_CONFIG_FILE)
}

/// 业务作用：解析 Naway pidfile 路径，确保信号发送端与运行进程使用同一品牌配置入口。
///
/// 参数说明: 无。
///
/// 返回：优先返回 `NAWAY_PIDFILE`，其次兼容 `GW_PIDFILE`，否则返回当前目录的 `naway.pid`。
pub(super) fn pidfile_path() -> PathBuf {
    std::env::var("NAWAY_PIDFILE")
        .or_else(|_| std::env::var("GW_PIDFILE"))
        .unwrap_or_else(|_| "naway.pid".to_string())
        .into()
}

/// 业务作用：`-s reload`:读 pidfile → 向进程发 SIGHUP。
pub(super) fn send_signal(sig: &str) -> Result<()> {
    if sig != "reload" {
        anyhow::bail!("unsupported signal `{sig}` (only `reload`)");
    }
    let pf = pidfile_path();
    // PID 最多十余字节；固定读 65 字节避免被篡改 pidfile 触发无界分配。
    let file =
        std::fs::File::open(&pf).with_context(|| format!("open pidfile {}", pf.display()))?;
    let mut bytes = Vec::with_capacity(16);
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 65), &mut bytes)
        .with_context(|| format!("read pidfile {}", pf.display()))?;
    anyhow::ensure!(
        bytes.len() <= 64,
        "pidfile {} exceeds 64 bytes",
        pf.display()
    );
    let raw_pid = std::str::from_utf8(&bytes)
        .with_context(|| format!("pidfile {} is not UTF-8", pf.display()))?;
    let pid = parse_reload_pid(raw_pid)?;
    // SAFETY: kill(2) 只发信号,不解引用指针。
    let rc = unsafe {
        libc::kill(pid, libc::SIGHUP)
    };
    if rc != 0 {
        anyhow::bail!(
            "kill {pid} SIGHUP failed: {}",
            std::io::Error::last_os_error()
        );
    }
    println!("sent SIGHUP to gateway pid {pid} (reload)");
    Ok(())
}

/// 业务作用：解析 `-s reload` 使用的 PID，并拒绝 Unix `kill(2)` 的进程组/广播特殊值。
///
/// 参数说明：
///
/// - `raw`：pidfile 的完整文本；允许外围空白，但只接受正 `i32` PID。
pub(super) fn parse_reload_pid(raw: &str) -> Result<i32> {
    let pid = raw.trim().parse::<i32>().context("parse pid")?;
    anyhow::ensure!(
        pid > 0,
        "pidfile must contain a positive process id; zero/negative values have process-group semantics"
    );
    Ok(pid)
}
