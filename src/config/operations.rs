//! 持久管理操作的独立资源声明；关闭时不解析数据库秘密或创建外部资源。

use anyhow::{ensure, Result};
use serde::Deserialize;
use std::{fmt, path::Path, sync::Arc};

pub(crate) const MAX_TARGETS: usize = 128;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub accept_proposals: bool,
    pub cluster_id: String,
    pub database_url: String,
    pub schema: String,
    pub max_records: u32,
    pub max_records_per_scope: u32,
    pub max_candidate_bytes: u32,
    pub max_total_candidate_bytes: u64,
    pub retention: Retention,
    pub workflow: Workflow,
    pub execution: Execution,
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Workflow {
    pub enabled: bool,
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Execution {
    pub enabled: bool,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    pub enabled: bool,
    pub epoch_window_seconds: u32,
    pub retain_seconds: u32,
    pub interval_seconds: u32,
    pub batch_size: u32,
}

impl Default for Retention {
    /// 业务作用：默认保留全部控制事实，只有显式开启后才启动有限清理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：十五分钟受理窗口、一天终态保留与每分钟最多三十二条的关闭策略。
    fn default() -> Self {
        Self {
            enabled: false,
            epoch_window_seconds: 900,
            retain_seconds: 86400,
            interval_seconds: 60,
            batch_size: 32,
        }
    }
}

impl Default for Config {
    /// 业务作用：保持持久管理默认关闭，并为显式启用提供固定资源上界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有数据库身份的关闭声明；开启必须另行提供集群和连接身份。
    fn default() -> Self {
        Self {
            enabled: false,
            accept_proposals: true,
            cluster_id: String::new(),
            database_url: String::new(),
            schema: String::new(),
            max_records: 4096,
            max_records_per_scope: 256,
            max_candidate_bytes: 1024 * 1024,
            max_total_candidate_bytes: 64 * 1024 * 1024,
            retention: Retention::default(),
            workflow: Workflow::default(),
            execution: Execution::default(),
        }
    }
}

impl fmt::Debug for Config {
    /// 业务作用：允许诊断资源开关和容量，同时隐藏数据库凭据及其来源。
    ///
    /// 参数说明：
    /// - `formatter`：配置诊断输出目标。
    ///
    /// 返回：仅含公开配置摘要的格式化结果。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsConfig")
            .field("enabled", &self.enabled)
            .field("accept_proposals", &self.accept_proposals)
            .field("cluster_id", &self.cluster_id)
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

/// 启动资源与连接秘密的冻结值；普通业务配置不能将记录迁往另一数据库。
#[derive(Clone, PartialEq, Eq)]
pub struct Plan {
    pub(crate) config: Config,
    pub(crate) database_url: Arc<str>,
}

impl Plan {
    /// 业务作用：在候选构建期验证持久操作权限与资源预算，不连接数据库。
    ///
    /// 参数说明：
    /// - `config`：原始持久操作声明。
    /// - `auth`：当前快照的已编译管理认证与权限目录。
    /// - `root`：数据库 SecretSource 的相对目录。
    ///
    /// 返回：关闭时为空；启用且满足独立制品、认证和边界要求时返回冻结计划。
    pub(crate) fn build(
        config: &Config,
        auth: &super::AdminAuthRuntimeCfg,
        root: &Path,
    ) -> Result<Option<Arc<Self>>> {
        if !config.enabled {
            return Ok(None);
        }
        ensure!(
            cfg!(feature = "admin-operations-pgsql"),
            "admin.operations requires admin-operations-pgsql"
        );
        ensure!(
            auth.enabled && auth.rbac_enabled,
            "admin.operations requires authentication and RBAC"
        );
        ensure!(
            !config.workflow.enabled || cfg!(feature = "admin-operations-workflow-pgsql"),
            "admin.operations.workflow requires admin-operations-workflow-pgsql"
        );
        ensure!(
            !config.execution.enabled
                || (config.workflow.enabled && cfg!(feature = "node-actions")),
            "admin.operations.execution requires workflow and node-actions"
        );
        ensure!(
            token(&config.cluster_id, 128),
            "invalid admin.operations.cluster_id"
        );
        ensure!(
            !config.schema.is_empty()
                && config.schema.len() <= 63
                && config
                    .schema
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && config
                    .schema
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                && !config.schema.starts_with("pg_")
                && config.schema != "information_schema",
            "invalid admin.operations.schema"
        );
        ensure!(
            (1..=4096).contains(&config.max_records)
                && (1..=config.max_records).contains(&config.max_records_per_scope)
                && (1024..=1024 * 1024).contains(&config.max_candidate_bytes)
                && (u64::from(config.max_candidate_bytes)..=64 * 1024 * 1024)
                    .contains(&config.max_total_candidate_bytes),
            "invalid admin.operations capacity"
        );
        let database_url = crate::security::secret::resolve_text(
            &config.database_url,
            root,
            "admin.operations.database_url",
        )?;
        let retention = &config.retention;
        ensure!(
            (60..=86400).contains(&retention.epoch_window_seconds)
                && (retention.epoch_window_seconds..=2678400).contains(&retention.retain_seconds)
                && (1..=3600).contains(&retention.interval_seconds)
                && (1..=128).contains(&retention.batch_size),
            "invalid admin.operations.retention bounds"
        );
        ensure!(
            database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"),
            "admin.operations requires a PostgreSQL URL"
        );
        Ok(Some(Arc::new(Self {
            config: config.clone(),
            database_url: database_url.into(),
        })))
    }

    /// 业务作用：区分可热关闭的受理及执行入口与必须重启才能迁移的持久权威。
    ///
    /// 参数说明：
    /// - `other`：尚未发布的候选计划。
    ///
    /// 返回：除受理与执行开关外所有资源和解析后的秘密相同时为真。
    pub(crate) fn same_bootstrap(&self, other: &Self) -> bool {
        let mut left = self.config.clone();
        let mut right = other.config.clone();
        left.accept_proposals = false;
        right.accept_proposals = false;
        left.execution.enabled = false;
        right.execution.enabled = false;
        left == right && self.database_url == other.database_url
    }
}

/// 业务作用：限制持久身份为稳定 ASCII token，避免数据库标识和路由路径歧义。
///
/// 参数说明：
/// - `value`：待校验的业务身份。
/// - `max`：所属字段的字节上限。
///
/// 返回：非空、界限内且只含字母数字及点横线下划线时为真。
pub(crate) fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// 业务作用：复验关闭或启用的整个启动权威，防止热更跨越已装配连接资源。
///
/// 参数说明：
/// - `current`：当前生效计划。
/// - `candidate`：拟发布计划。
///
/// 返回：两者均关闭或启用且资源相同才允许发布。
pub(crate) fn same_bootstrap(current: Option<&Plan>, candidate: Option<&Plan>) -> bool {
    match (current, candidate) {
        (None, None) => true,
        (Some(current), Some(candidate)) => current.same_bootstrap(candidate),
        _ => false,
    }
}
