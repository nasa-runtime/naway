//! Redis 配置正文只读；复用 NASA 连接与协议标记合同，读取前在同一原子操作中限制正文大小。

use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use nasa::redis::{CompatibilityProfile, RedisClient, RedisCommand, RedisConfig};
use tokio::sync::OnceCell;

use super::model::{identifier, Declaration};
use crate::config::providers::RedisSecurityCfg;

pub(super) struct Reader {
    config: RedisConfig,
    key: String,
    client: OnceCell<Arc<RedisClient>>,
}

impl Reader {
    /// 业务作用：冻结单一 Redis 文档键与认证权威，拒绝公网明文、URL 凭据及协议标记键混用。
    ///
    /// 参数说明：
    /// - `endpoint`：固定连接和正文身份
    /// - `key`：固定连接和正文身份
    /// - `namespace`：固定连接和正文身份
    /// - `security`：为本地认证声明与已解析秘密
    /// - `password`：为本地认证声明与已解析秘密
    /// - `deadline_ms`：限制命令与建连。
    ///
    /// 返回：无网络副作用的惰性读取计划；非法地址、凭据、键名或命名空间拒绝。
    pub(super) fn build(
        endpoint: &str,
        key: &str,
        namespace: &str,
        security: &RedisSecurityCfg,
        password: String,
        deadline_ms: u64,
    ) -> Result<Self> {
        ensure!(
            endpoint.len() <= 2048
                && !endpoint.contains(['\\', '$', '?', '#', '@', '%'])
                && !endpoint.chars().any(char::is_control),
            "invalid Redis provider endpoint"
        );
        let mut url = reqwest::Url::parse(endpoint)
            .map_err(|_| anyhow::anyhow!("invalid Redis provider endpoint"))?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            url.host_str().is_some()
                && url.port().is_some_and(|port| port != 0)
                && url.username().is_empty()
                && url.password().is_none()
                && (url.scheme() == "rediss"
                    || (url.scheme() == "redis" && security.allow_loopback_plaintext && loopback)),
            "Redis provider requires authenticated TLS or explicit IP loopback plaintext"
        );
        let database = url.path().strip_prefix('/').unwrap_or(url.path());
        ensure!(
            database.is_empty()
                || (database.bytes().all(|byte| byte.is_ascii_digit())
                    && database.parse::<u16>().is_ok()),
            "invalid Redis provider database"
        );
        ensure!(
            identifier(namespace),
            "invalid Redis provider protocol namespace"
        );
        ensure!(
            !key.is_empty()
                && key.len() <= 512
                && !key.chars().any(char::is_control)
                && !key.starts_with("nasa:protocol:"),
            "invalid Redis provider document key"
        );
        ensure!(
            !password.is_empty()
                && password.len() <= 4096
                && !password.chars().any(char::is_control)
                && security.username.len() <= 128
                && !security.username.chars().any(char::is_control),
            "invalid Redis provider credential"
        );
        url.set_username(&security.username)
            .map_err(|_| anyhow::anyhow!("invalid Redis provider username"))?;
        url.set_password(Some(&password))
            .map_err(|_| anyhow::anyhow!("invalid Redis provider password"))?;
        let mut config = RedisConfig::new(url.as_str(), namespace, CompatibilityProfile::RustV2);
        config.command.response_timeout_ms = deadline_ms;
        config.command.timeout_ms = deadline_ms;
        config
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid Redis provider connection plan"))?;
        Ok(Self {
            config,
            key: key.into(),
            client: OnceCell::new(),
        })
    }

    /// 业务作用：获取受大小限制的完整声明，缺键、超限或无版本删除不能为旧路由续期。
    ///
    /// 参数说明：
    /// - `maximum`：为本地声明的正文上限；整个操作另受来源绝对 deadline 约束。
    ///
    /// 返回：仅成功读取并解析的声明；任何失败不更改已发布水位或事实源正文。
    pub(super) async fn read(&self, maximum: usize) -> Result<Declaration> {
        let client = self
            .client
            .get_or_try_init(|| async {
                // NASA 建连只创建/验证专用协议标记；配置键权限不因此获得 SET 或 DEL 授权。
                RedisClient::connect(self.config.clone())
                    .await
                    .map_err(|_| anyhow::anyhow!("Redis provider connection unavailable"))
            })
            .await?;
        // 长度与正文必须在同一个只读脚本中观察，不能让 STRLEN 与 GET 之间的写入绕过内存预算。
        let script = include_str!("redis/read.lua");
        let mut command = RedisCommand::new();
        command
            .arg("EVAL_RO")
            .arg(script)
            .arg(1)
            .arg(&self.key)
            .arg(maximum);
        let bytes: Option<Vec<u8>> = client
            .execute_raw(&command)
            .await
            .map_err(|_| anyhow::anyhow!("Redis provider document unavailable"))?;
        let bytes = bytes.context("Redis provider document absent")?;
        ensure!(
            bytes.len() <= maximum,
            "Redis provider document byte budget reached"
        );
        crate::config::document::decode(&bytes, maximum)
            .map_err(|_| anyhow::anyhow!("Redis provider document rejected"))
    }
}
