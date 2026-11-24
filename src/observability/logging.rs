//! 进程全局兜底日志的 NASA 配置适配与有序退役。

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use nasa::log::{LogConfig, LogContext, LogGuard};

/// 已验证的启动日志声明；省略时保留控制台与 `RUST_LOG` 的默认行为。
#[derive(Clone, Debug)]
pub struct LogPlan {
    config: Option<LogConfig>,
    signature: Arc<str>,
}

impl LogPlan {
    /// 业务作用：在候选构建期验证日志配置，不因 dry-run 或被拒绝的候选打开文件。
    ///
    /// 参数说明：
    /// - `config`：naml 已完成环境占位符求值的可选 `log` 配置。
    ///
    /// 返回：配置合法时返回启动计划；未解析目录、级别、格式或滚动参数非法时拒绝候选。
    pub(crate) fn build(config: Option<LogConfig>) -> Result<Self> {
        let signature = match &config {
            Some(config) => {
                // 主文档允许保留请求期变量，日志目录却不能把未求值占位符当作真实路径创建。
                anyhow::ensure!(
                    !config
                        .path
                        .as_deref()
                        .is_some_and(|path| path.contains("${")),
                    "log.path contains an unresolved placeholder"
                );
                let resolved = config
                    .resolve(&LogContext::console_only())
                    .context("invalid process log configuration")?;
                tracing_subscriber::EnvFilter::try_new(&resolved.level)
                    .context("invalid log.level")?;
                // 指纹只在配置构建期形成，同进程比较解析后的语义，别名或容量单位不触发无效换代。
                format!("{resolved:?}").into()
            }
            None => Arc::from("console-default"),
        };
        Ok(Self {
            config,
            signature,
        })
    }

    /// 业务作用：比较两个候选的实际日志配置，避免无关业务换版重开文件。
    ///
    /// 参数说明：
    /// - `candidate`：尚未发布的候选日志计划。
    ///
    /// 返回：解析后的日志声明一致时为真，可复用当前输出。
    pub(crate) fn same_bootstrap(&self, candidate: &Self) -> bool {
        self.signature == candidate.signature
    }

    /// 业务作用：在 tracing 与 OpenTelemetry 共用的 subscriber 建立后启用 NASA 滚动文件输出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件打开成功时返回必须持有至停机的刷盘守卫；未声明文件日志时为空；失败阻止开放 listener。
    fn start(&self) -> Result<Option<LogGuard>> {
        self.config
            .as_ref()
            .map(|config| {
                nasa::log::apply_config(config, &LogContext::console_only())
                    .context("open process log output")
            })
            .transpose()
            .map(Option::flatten)
    }
}

/// 唯一的进程兜底日志 owner；退役 writer 由原调用方在发布锁外刷盘。
pub struct ProcessLog {
    state: Mutex<Active>,
}

struct Active {
    file: Option<LogGuard>,
    closed: bool,
}

impl ProcessLog {
    /// 业务作用：在开放监听前建立全局兜底输出，将刷盘与热更所有权留在运行期。
    ///
    /// 参数说明：
    /// - `plan`：初始配置的已验证日志声明。
    ///
    /// 返回：初始输出已经安装的 owner，打开文件失败阻止启动。
    pub fn open(plan: &LogPlan) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            state: Mutex::new(Active {
                file: plan.start()?,
                closed: false,
            }),
        }))
    }

    /// 业务作用：在发布全局兜底配置前接管新 writer，打开失败时保留现有日志输出。
    ///
    /// 参数说明：
    /// - `plan`：已完成配置校验和其它资源门禁的同代日志计划。
    ///
    /// 返回：成功移交旧输出供调用者在发布锁外刷盘，关停或候选打开失败时返回错误。
    pub(crate) fn install(&self, plan: &LogPlan) -> Result<Option<LogGuard>> {
        let mut active = self.state.lock().expect("process log owner poisoned");
        anyhow::ensure!(!active.closed, "process log output is closed");
        let fallback = LogConfig {
            level: tracing_subscriber::EnvFilter::try_from_default_env()
                .map(|filter| filter.to_string())
                .unwrap_or_else(|_| "gateway=info,info".to_owned()),
            ..LogConfig::default()
        };
        // nalog 先打开候选输出才能替换全局文件槽。候选没有配置时显式切回控制台。
        let file = nasa::log::apply_config(
            plan.config.as_ref().unwrap_or(&fallback),
            &LogContext::console_only(),
        )
        .context("open candidate process log output")?;
        Ok(std::mem::replace(&mut active.file, file))
    }

    /// 业务作用：网关排空后撤销新 writer 的安装权，并刷完当前文件日志。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：停止本进程文件输出后返回；可能等待后台文件写入结束。
    pub fn shutdown(&self) {
        let mut active = self.state.lock().expect("process log owner poisoned");
        active.closed = true;
        nasa::log::disable_file_logging();
        let file = active.file.take();
        drop(active);
        drop(file);
    }
}
