//! 进程日志的 NASA 配置适配；文件 writer 与进程同寿命。

use std::sync::Arc;

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

    /// 业务作用：复验候选是否要求替换与进程同寿命的日志 writer。
    ///
    /// 参数说明：
    /// - `candidate`：尚未发布的候选日志计划。
    ///
    /// 返回：解析后的日志声明一致时为真；不同则必须重启后生效。
    pub(crate) fn same_bootstrap(&self, candidate: &Self) -> bool {
        self.signature == candidate.signature
    }

    /// 业务作用：在 tracing 与 OpenTelemetry 共用的 subscriber 建立后启用 NASA 滚动文件输出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件打开成功时返回必须持有至停机的刷盘守卫；未声明文件日志时为空；失败阻止开放 listener。
    pub fn start(&self) -> Result<Option<LogGuard>> {
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
