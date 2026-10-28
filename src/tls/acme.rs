//! ACME 证书自动化运行时：HTTP-01 临时响应、签发/续期 worker 与证书原子落盘。
//!
//! 请求热路径只在固定前缀命中后读取 challenge 表；正常业务 path 只有一次 `starts_with`，不会加锁。
//! ACME 网络交互、证书解析和文件同步全部在控制面后台任务执行。

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use hyper::{Response, StatusCode};
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{AcmeChallenge, AcmeDns01ProviderRuntime, AcmeRuntimeCfg, TlsRuntimeCfg};
use crate::{full_body, BoxBody};

/// RFC 8555 HTTP-01 challenge 的固定 URI 前缀。
const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
/// instant-acme 账户 JSON 的控制面硬上限；正常凭据只有数 KiB，1 MiB 为密钥格式扩展留足余量。
const MAX_ACME_ACCOUNT_CREDENTIAL_BYTES: usize = 1024 * 1024;
/// ACME leaf/chain 文件硬上限，与 TLS 构建器一致；续期检查不能绕过 TLS 有界读取。
const MAX_ACME_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;

/// 进程常驻 HTTP-01 challenge 表。
///
/// ACME worker 只在验证窗口插入少量 token；数据面只在 path 命中固定前缀后获取读锁。value 用 `Bytes`
/// 保存，构造响应时 clone 只增加引用计数，不复制 key-authorization 内容。
#[derive(Default)]
pub struct Http01ChallengeStore {
    /// token -> key authorization 响应体。
    challenges: RwLock<HashMap<String, Bytes>>,
}

impl Http01ChallengeStore {
    /// 业务作用：创建一个空 challenge 表。
    ///
    /// 返回：可由所有 proxy 与 ACME worker 共享的常驻句柄。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 业务作用：在 ACME 验证窗口发布一个 token。
    ///
    /// 参数说明：
    /// - `token`: ACME server 给出的 URL-safe challenge token。
    /// - `key_authorization`: 账户公钥 thumbprint 参与生成的公开响应值。
    ///
    /// token 为空或包含 `/` 时拒绝发布，避免挑战入口被滥用成任意 path 映射。
    pub fn insert(&self, token: &str, key_authorization: &str) -> anyhow::Result<()> {
        if token.is_empty() || token.as_bytes().contains(&b'/') {
            anyhow::bail!("invalid ACME HTTP-01 token");
        }
        self.challenges
            .write()
            .expect("ACME HTTP-01 store poisoned")
            .insert(
                token.to_owned(),
                Bytes::copy_from_slice(key_authorization.as_bytes()),
            );
        Ok(())
    }

    /// 业务作用：移除一个已完成/失败订单的 token。
    ///
    /// 参数说明：
    /// - `token`: 先前发布的 challenge token。
    pub fn remove(&self, token: &str) {
        self.challenges
            .write()
            .expect("ACME HTTP-01 store poisoned")
            .remove(token);
    }

    /// 业务作用：尝试为当前请求构造 HTTP-01 响应。
    ///
    /// 参数说明：
    /// - `parts`: 已完成基础 URI 解析的下游请求 head。
    ///
    /// 返回：仅 GET 且 path 精确命中已发布 token 时返回 `text/plain` 200；其它请求返回 `None`，继续
    /// 正常 redirect/guard/router 管线。响应 body 是共享 `Bytes`，不做字符串重建。
    pub fn response(&self, parts: &http::request::Parts) -> Option<Response<BoxBody>> {
        if parts.method != http::Method::GET {
            return None;
        }
        let token = parts.uri.path().strip_prefix(HTTP01_PREFIX)?;
        if token.is_empty() || token.as_bytes().contains(&b'/') {
            return None;
        }
        let body = self
            .challenges
            .read()
            .expect("ACME HTTP-01 store poisoned")
            .get(token)
            .cloned()?;
        Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(full_body(body))
                .expect("static ACME HTTP-01 response"),
        )
    }
}

/// 一次订单发布的 HTTP-01 token 集合；Drop 无条件清理，覆盖成功、错误与 task 取消。
pub struct Http01ChallengeLease {
    /// 共享 challenge 表。
    store: Arc<Http01ChallengeStore>,
    /// 本订单已经发布的 token。
    tokens: Vec<String>,
}

impl Http01ChallengeLease {
    /// 业务作用：为一个 ACME order 创建空租约。
    ///
    /// 参数说明：
    /// - `store`: 数据面正在读取的共享 HTTP-01 表。
    ///
    /// 返回：可逐个发布 token 的 RAII 租约。
    pub fn new(store: Arc<Http01ChallengeStore>) -> Self {
        Self {
            store,
            tokens: Vec::new(),
        }
    }

    /// 业务作用：发布 token 并纳入自动清理集合。
    ///
    /// 参数说明：
    /// - `token`: ACME challenge token。
    /// - `key_authorization`: HTTP-01 响应体。
    pub fn insert(&mut self, token: &str, key_authorization: &str) -> anyhow::Result<()> {
        self.store.insert(token, key_authorization)?;
        self.tokens.push(token.to_owned());
        Ok(())
    }
}

impl Drop for Http01ChallengeLease {
    /// 业务作用：订单退出时撤下全部公开 challenge，防止旧 token 长期残留。
    fn drop(&mut self) {
        for token in &self.tokens {
            self.store.remove(token);
        }
    }
}

/// ACME worker 使用的互斥后端。
///
/// 单节点用 Tokio owned mutex；多节点用 `nasa::redis::DistributedLock` 的租约与看门狗，锁丢失后
/// Redis guard 会停止续租。签发结果写入共享文件卷，由各节点既有证书 watcher 热换。
enum AcmeLockBackend {
    /// 单进程内互斥，只适用于 `storage_mode=local-file` 的单节点部署。
    Local(Arc<tokio::sync::Mutex<()>>),
    /// Redis 分布式租约锁；仅在 `redis-runtime` feature 下可构建。
    #[cfg(feature = "redis-runtime")]
    Redis(Arc<nasa::redis::DistributedLock>),
}

/// DNS-01 provider 的最小生命周期契约。
///
/// provider 只负责发布/清理一个 TXT 值；ACME order、传播等待、超时与取消清理由网关统一治理。
pub trait Dns01Provider: Send + Sync {
    /// 业务作用：发布一个 `_acme-challenge` TXT 值。
    ///
    /// 参数说明：
    /// - `record`: 不带尾点的完整 TXT record name。
    /// - `value`: RFC 8555 key authorization digest。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// 业务作用：清理先前发布的 TXT 值；实现必须幂等，允许错误/取消路径重复调用。
    ///
    /// 参数说明：
    /// - `record`: 先前发布的 record name。
    /// - `value`: 只删除本订单的值，不能误删同名并行 TXT。
    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// 通过直接 exec 外部程序实现的 DNS-01 provider。
///
/// action/record/value 只放环境变量，不经过 shell、也不进入 argv/日志；provider 自己可从 env/file/K8s
/// Secret/Vault 读取云厂商凭据。
struct CommandDns01Provider {
    command: PathBuf,
    args: Arc<[String]>,
    timeout: Duration,
}

impl CommandDns01Provider {
    /// 业务作用：在固定 deadline 内直接执行 DNS provider，不经 shell 且不暴露 challenge 到 argv。
    ///
    /// 参数说明：
    /// - `action`：只能是固定 present/cleanup
    /// - `record`：只进入子进程环境。
    /// - `value`：只进入子进程环境。
    ///
    /// 返回：命令按时以成功状态退出时成功；启动、超时或非零退出均失败闭合。
    async fn run(&self, action: &'static str, record: &str, value: &str) -> Result<()> {
        let mut command = tokio::process::Command::new(&self.command);
        command
            .args(self.args.iter())
            .env("GW_ACME_DNS_ACTION", action)
            .env("GW_ACME_DNS_RECORD", record)
            .env("GW_ACME_DNS_VALUE", value)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let status = tokio::time::timeout(self.timeout, command.status())
            .await
            .with_context(|| format!("ACME DNS-01 provider {action} timeout"))?
            .with_context(|| format!("execute ACME DNS-01 provider {action}"))?;
        if !status.success() {
            // provider 输出可能含云凭据，错误只暴露退出码，不回显 stdout/stderr。
            anyhow::bail!("ACME DNS-01 provider {action} failed with status {status}");
        }
        Ok(())
    }
}

impl Dns01Provider for CommandDns01Provider {
    /// 业务作用：向固定 DNS provider 提交当前 ACME challenge 的 TXT 记录，不改变其它域名记录。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.run("present", record, value))
    }

    /// 业务作用：撤销当前 challenge 创建的 TXT 值，避免清理影响同名的其它签发任务。
    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.run("cleanup", record, value))
    }
}

#[derive(Clone)]
struct HttpDns01Limits {
    timeout: Duration,
    retry_attempts: usize,
    retry_backoff: Duration,
    max_response_bytes: usize,
    ttl_seconds: u32,
}

/// Cloudflare DNS Records API provider；record id 只保存在本进程内且有固定容量。
struct CloudflareDns01Provider {
    client: reqwest::Client,
    api_base: String,
    zone_id: String,
    api_token: String,
    limits: HttpDns01Limits,
    record_ids: std::sync::Mutex<HashMap<(String, String), String>>,
}

impl CloudflareDns01Provider {
    /// 业务作用：调用固定 Cloudflare zone authority，并对网络、状态码、重试和响应体统一设硬门。
    ///
    /// 参数说明：
    /// - `method`：已校验 provider 配置派生的 HTTP 方法。
    /// - `url`：已校验 provider 配置派生的固定目标 URL。
    /// - `body`：仅包含公开 TXT challenge 的可选请求体。
    /// - `query`：固定操作所需的查询参数。
    ///
    /// 返回：获得 2xx 且完整响应不超限时返回字节；认证、输入、超限或最终依赖故障失败闭合。
    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&serde_json::Value>,
        query: Option<&[(&str, &str)]>,
    ) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + self.limits.timeout;
        let mut last_error = None;
        for attempt in 0..self.limits.retry_attempts {
            let mut request = self
                .client
                .request(method.clone(), url)
                .bearer_auth(&self.api_token);
            if let Some(body) = body {
                request = request.json(body);
            }
            if let Some(query) = query {
                request = request.query(query);
            }
            let result = tokio::time::timeout_at(deadline, request.send()).await;
            match result {
                Ok(Ok(response)) if response.status().is_success() => {
                    return read_bounded_http_body(response, self.limits.max_response_bytes).await;
                }
                Ok(Ok(response)) => {
                    let status = response.status();
                    let _ = read_bounded_http_body(response, self.limits.max_response_bytes).await;
                    if !status.is_server_error() && status.as_u16() != 429 {
                        anyhow::bail!("Cloudflare DNS API rejected request with status {status}");
                    }
                    last_error = Some(anyhow::anyhow!(
                        "Cloudflare DNS API temporary status {status}"
                    ));
                }
                Ok(Err(error)) => {
                    last_error = Some(anyhow::Error::new(error).context("call Cloudflare DNS API"));
                }
                Err(_) => anyhow::bail!("Cloudflare DNS API operation timeout"),
            }
            if attempt + 1 < self.limits.retry_attempts {
                tokio::time::timeout_at(deadline, tokio::time::sleep(self.limits.retry_backoff))
                    .await
                    .context("Cloudflare DNS API retry deadline exceeded")?;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Cloudflare DNS API failed")))
    }

    /// 业务作用：创建本订单唯一 TXT 并冻结返回的 record id，供取消路径精确回收。
    ///
    /// 参数说明：
    /// - `record`：来自当前 ACME authorization。
    /// - `value`：来自当前 ACME authorization。
    ///
    /// 返回：Cloudflare 确认创建并返回合法 id 时成功；映射容量或响应结构异常时立即清理并失败。
    async fn present_record(&self, record: &str, value: &str) -> Result<()> {
        anyhow::ensure!(
            value.len() <= 255,
            "ACME DNS-01 TXT value exceeds 255 bytes"
        );
        let url = format!("{}/zones/{}/dns_records", self.api_base, self.zone_id);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record,
            "content": value,
            "ttl": self.limits.ttl_seconds,
        });
        let bytes = self
            .request(reqwest::Method::POST, &url, Some(&body), None)
            .await?;
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).context("parse Cloudflare DNS create response")?;
        anyhow::ensure!(
            document.get("success").and_then(serde_json::Value::as_bool) == Some(true),
            "Cloudflare DNS create response did not report success"
        );
        let id = document
            .pointer("/result/id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
            .context("Cloudflare DNS create response has invalid record id")?
            .to_owned();
        let over_capacity = {
            let ids = self
                .record_ids
                .lock()
                .map_err(|_| anyhow::anyhow!("Cloudflare DNS record map is poisoned"))?;
            ids.len() >= 256 && !ids.contains_key(&(record.to_owned(), value.to_owned()))
        };
        if over_capacity {
            let _ = self.delete_id(&id).await;
            anyhow::bail!("Cloudflare DNS outstanding record limit exceeded");
        }
        self.record_ids
            .lock()
            .map_err(|_| anyhow::anyhow!("Cloudflare DNS record map is poisoned"))?
            .insert((record.to_owned(), value.to_owned()), id);
        Ok(())
    }

    /// 业务作用：按 Cloudflare record id 幂等删除单个 challenge，不影响同名并行 TXT。
    ///
    /// 参数说明：
    /// - `id`：是 create/list 返回并经过字符门校验的固定标识。
    ///
    /// 返回：2xx 或已不存在时成功；其它最终错误保留给租约重试/告警。
    async fn delete_id(&self, id: &str) -> Result<()> {
        let url = format!("{}/zones/{}/dns_records/{id}", self.api_base, self.zone_id);
        match self
            .request(reqwest::Method::DELETE, &url, None, None)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if format!("{error:#}").contains("404") => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// 业务作用：恢复缺失的本地 record id 后精确删除本订单 TXT，使重复 cleanup 仍保持幂等。
    ///
    /// 参数说明：
    /// - `record`：共同构成完整删除键。
    /// - `value`：共同构成完整删除键。
    ///
    /// 返回：所有匹配 id 已删除或记录不存在时成功；列表异常、超限或删除失败时返回错误。
    async fn cleanup_record(&self, record: &str, value: &str) -> Result<()> {
        let key = (record.to_owned(), value.to_owned());
        let known_id = {
            self.record_ids
                .lock()
                .map_err(|_| anyhow::anyhow!("Cloudflare DNS record map is poisoned"))?
                .remove(&key)
        };
        if let Some(id) = known_id {
            return self.delete_id(&id).await;
        }
        let url = format!("{}/zones/{}/dns_records", self.api_base, self.zone_id);
        let query = [
            ("type", "TXT"),
            ("name", record),
            ("content", value),
            ("per_page", "100"),
        ];
        let bytes = self
            .request(reqwest::Method::GET, &url, None, Some(&query))
            .await?;
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).context("parse Cloudflare DNS list response")?;
        let records = document
            .get("result")
            .and_then(serde_json::Value::as_array)
            .context("Cloudflare DNS list response has no result array")?;
        anyhow::ensure!(
            records.len() <= 100,
            "Cloudflare DNS list result exceeds 100 records"
        );
        for record_value in records {
            if record_value.get("type").and_then(serde_json::Value::as_str) != Some("TXT")
                || record_value.get("name").and_then(serde_json::Value::as_str) != Some(record)
                || record_value
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    != Some(value)
            {
                continue;
            }
            let id = record_value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 128
                        && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
                .context("Cloudflare DNS list returned invalid record id")?;
            self.delete_id(id).await?;
        }
        Ok(())
    }
}

impl Dns01Provider for CloudflareDns01Provider {
    /// 业务作用：向固定 DNS provider 提交当前 ACME challenge 的 TXT 记录，不改变其它域名记录。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.present_record(record, value))
    }

    /// 业务作用：撤销当前 challenge 创建的 TXT 值，避免清理影响同名的其它签发任务。
    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.cleanup_record(record, value))
    }
}

/// Vault 固定 action endpoint provider；Vault policy 决定 token 仅能调用两个配置 path。
struct VaultDns01Provider {
    client: reqwest::Client,
    endpoint: String,
    token: String,
    namespace: Option<String>,
    present_path: String,
    cleanup_path: String,
    limits: HttpDns01Limits,
}

impl VaultDns01Provider {
    /// 业务作用：向固定 Vault action path 提交有界 challenge，不允许重定向把 token 带到其它 authority。
    ///
    /// 参数说明：
    /// - `path`：构建期校验的 DNS provider 操作路径。
    /// - `record`：公开 DNS challenge 记录名。
    /// - `value`：公开 TXT challenge 值。
    /// - `cleanup`：是否执行 challenge 清理动作。
    ///
    /// 返回：Vault 返回 2xx 或 cleanup 返回 404 时成功；其它客户端拒绝和最终依赖失败均失败闭合。
    async fn action(&self, path: &str, record: &str, value: &str, cleanup: bool) -> Result<()> {
        let url = format!("{}/{}", self.endpoint, path);
        let deadline = tokio::time::Instant::now() + self.limits.timeout;
        let body = serde_json::json!({
            "name": record,
            "value": value,
            "ttl": self.limits.ttl_seconds,
        });
        let mut last_error = None;
        for attempt in 0..self.limits.retry_attempts {
            let mut request = self
                .client
                .post(&url)
                .header("X-Vault-Token", &self.token)
                .json(&body);
            if let Some(namespace) = &self.namespace {
                request = request.header("X-Vault-Namespace", namespace);
            }
            match tokio::time::timeout_at(deadline, request.send()).await {
                Ok(Ok(response)) if response.status().is_success() => {
                    read_bounded_http_body(response, self.limits.max_response_bytes).await?;
                    return Ok(());
                }
                Ok(Ok(response))
                    if cleanup && response.status() == reqwest::StatusCode::NOT_FOUND =>
                {
                    read_bounded_http_body(response, self.limits.max_response_bytes).await?;
                    return Ok(());
                }
                Ok(Ok(response)) => {
                    let status = response.status();
                    let _ = read_bounded_http_body(response, self.limits.max_response_bytes).await;
                    if !status.is_server_error() && status.as_u16() != 429 {
                        anyhow::bail!("Vault DNS action rejected request with status {status}");
                    }
                    last_error = Some(anyhow::anyhow!(
                        "Vault DNS action temporary status {status}"
                    ));
                }
                Ok(Err(error)) => {
                    last_error = Some(anyhow::Error::new(error).context("call Vault DNS action"));
                }
                Err(_) => anyhow::bail!("Vault DNS action timeout"),
            }
            if attempt + 1 < self.limits.retry_attempts {
                tokio::time::timeout_at(deadline, tokio::time::sleep(self.limits.retry_backoff))
                    .await
                    .context("Vault DNS action retry deadline exceeded")?;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Vault DNS action failed")))
    }
}

impl Dns01Provider for VaultDns01Provider {
    /// 业务作用：向固定 DNS provider 提交当前 ACME challenge 的 TXT 记录，不改变其它域名记录。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.action(&self.present_path, record, value, false))
    }

    /// 业务作用：撤销当前 challenge 创建的 TXT 值，避免清理影响同名的其它签发任务。
    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.action(&self.cleanup_path, record, value, true))
    }
}

/// 业务作用：读取 HTTP provider 响应时执行增量硬门，避免错误页或恶意端点撑高控制面内存。
///
/// 参数说明：
/// - `response`：是禁用重定向客户端返回的响应
/// - `limit`：是配置期约束后的字节上限。
///
/// 返回：完整 body 不超过上限时返回；传输错误或多出任一字节即失败。
async fn read_bounded_http_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("ACME DNS provider response exceeds {limit} bytes");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read ACME DNS provider response")?;
        anyhow::ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "ACME DNS provider response exceeds {limit} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// RFC2136 DNS UPDATE provider；所有请求走 TCP，并用 HMAC-SHA256 TSIG 同时认证请求与响应。
struct Rfc2136Dns01Provider {
    server: std::net::SocketAddr,
    zone: String,
    tsig_key_name: String,
    tsig_secret: Arc<[u8]>,
    ttl_seconds: u32,
    timeout: Duration,
    retry_attempts: usize,
    retry_backoff: Duration,
}

impl Rfc2136Dns01Provider {
    /// 业务作用：在总 deadline 内执行带 TSIG 的 DNS UPDATE；cleanup 只删除完全匹配的 TXT RR。
    ///
    /// 参数说明：
    /// - `record`：是本订单 challenge
    /// - `value`：是本订单 challenge
    /// - `cleanup`：决定 IN 新增或 NONE 精确删除。
    ///
    /// 返回：权威 DNS 返回经 TSIG 验证的 NOERROR 时成功；超时、网络、认证或 DNS 错误均失败。
    async fn update(&self, record: &str, value: &str, cleanup: bool) -> Result<()> {
        let record = normalize_dns_wire_name(record)?;
        anyhow::ensure!(
            record == self.zone || record.ends_with(&format!(".{}", self.zone)),
            "ACME RFC2136 record is outside configured zone"
        );
        anyhow::ensure!(
            value.len() <= 255,
            "ACME RFC2136 TXT value exceeds 255 bytes"
        );
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut last_error = None;
        for attempt in 0..self.retry_attempts {
            match tokio::time::timeout_at(deadline, self.update_once(&record, value, cleanup)).await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => anyhow::bail!("ACME RFC2136 operation timeout"),
            }
            if attempt + 1 < self.retry_attempts {
                tokio::time::timeout_at(deadline, tokio::time::sleep(self.retry_backoff))
                    .await
                    .context("ACME RFC2136 retry deadline exceeded")?;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("ACME RFC2136 update failed")))
    }

    /// 业务作用：完成一次 TCP DNS UPDATE 并认证对应响应，防止伪造成功导致 ACME 无效等待。
    ///
    /// 参数说明：
    /// - `record`：已通过 zone 与 DNS name 校验的 challenge 记录名。
    /// - `value`：已通过长度校验的公开 TXT challenge。
    /// - `cleanup`：是否执行删除记录的 UPDATE 动作。
    ///
    /// 返回：请求完整写出且响应 ID/opcode/rcode/TSIG/MAC 全部一致时成功。
    async fn update_once(&self, record: &str, value: &str, cleanup: bool) -> Result<()> {
        let mut id_bytes = [0_u8; 2];
        getrandom::getrandom(&mut id_bytes).context("generate RFC2136 transaction id")?;
        let id = u16::from_be_bytes(id_bytes);
        let (request, request_mac) = build_rfc2136_request(
            id,
            &self.zone,
            record,
            value,
            cleanup,
            self.ttl_seconds,
            &self.tsig_key_name,
            &self.tsig_secret,
        )?;
        anyhow::ensure!(
            request.len() <= u16::MAX as usize,
            "RFC2136 request exceeds TCP DNS limit"
        );
        let mut stream = tokio::net::TcpStream::connect(self.server)
            .await
            .with_context(|| format!("connect RFC2136 authority {}", self.server))?;
        stream
            .write_all(&(request.len() as u16).to_be_bytes())
            .await
            .context("write RFC2136 TCP length")?;
        stream
            .write_all(&request)
            .await
            .context("write RFC2136 request")?;
        stream.flush().await.context("flush RFC2136 request")?;
        let response_len = stream
            .read_u16()
            .await
            .context("read RFC2136 TCP response length")? as usize;
        anyhow::ensure!(
            (12..=u16::MAX as usize).contains(&response_len),
            "invalid RFC2136 response length"
        );
        let mut response = vec![0_u8; response_len];
        stream
            .read_exact(&mut response)
            .await
            .context("read RFC2136 response")?;
        verify_rfc2136_response(
            &response,
            id,
            &self.tsig_key_name,
            &self.tsig_secret,
            &request_mac,
        )
    }
}

impl Dns01Provider for Rfc2136Dns01Provider {
    /// 业务作用：向固定 DNS provider 提交当前 ACME challenge 的 TXT 记录，不改变其它域名记录。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.update(record, value, false))
    }

    /// 业务作用：撤销当前 challenge 创建的 TXT 值，避免清理影响同名的其它签发任务。
    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.update(record, value, true))
    }
}

type HmacSha256 = Hmac<sha2::Sha256>;
const TSIG_ALGORITHM: &str = "hmac-sha256";
const TSIG_FUDGE_SECONDS: u16 = 300;

/// 业务作用：编码并签名一条 RFC2136 TXT UPDATE，确保删除语义只命中本订单的精确 RDATA。
///
/// 参数说明：
/// - `id`：本次 DNS UPDATE 的请求标识。
/// - `zone`：已经验证的权威 DNS zone。
/// - `record`：已经验证的 challenge 记录名称。
/// - `value`：已经验证长度的 TXT challenge 值。
/// - `cleanup`：是否使用 class NONE 删除本次 challenge。
/// - `ttl_seconds`：新增 TXT 记录的 TTL 秒数。
/// - `key_name`：已经校验的 TSIG 密钥名称。
/// - `secret`：构建期解析的 TSIG 密钥材料。
///
/// 返回：返回含 TSIG 的完整 DNS message 及请求 MAC，供响应 TSIG 链式验证。
#[allow(clippy::too_many_arguments)]
fn build_rfc2136_request(
    id: u16,
    zone: &str,
    record: &str,
    value: &str,
    cleanup: bool,
    ttl_seconds: u32,
    key_name: &str,
    secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut unsigned = Vec::with_capacity(512);
    push_u16(&mut unsigned, id);
    push_u16(&mut unsigned, 5 << 11);
    push_u16(&mut unsigned, 1);
    push_u16(&mut unsigned, 0);
    push_u16(&mut unsigned, 1);
    push_u16(&mut unsigned, 0);
    encode_dns_name(&mut unsigned, zone)?;
    push_u16(&mut unsigned, 6);
    push_u16(&mut unsigned, 1);
    encode_dns_name(&mut unsigned, record)?;
    push_u16(&mut unsigned, 16);
    push_u16(
        &mut unsigned,
        if cleanup {
            254
        } else {
            1
        },
    );
    push_u32(
        &mut unsigned,
        if cleanup {
            0
        } else {
            ttl_seconds
        },
    );
    push_u16(&mut unsigned, value.len() as u16 + 1);
    unsigned.push(value.len() as u8);
    unsigned.extend_from_slice(value.as_bytes());

    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let mut mac_input = unsigned.clone();
    append_tsig_variables(
        &mut mac_input,
        key_name,
        TSIG_ALGORITHM,
        signed_at,
        TSIG_FUDGE_SECONDS,
        0,
        &[],
    )?;
    let mut signer = HmacSha256::new_from_slice(secret).context("initialize RFC2136 TSIG")?;
    signer.update(&mac_input);
    let mac = signer.finalize().into_bytes().to_vec();

    let mut request = unsigned;
    request[10..12].copy_from_slice(&1_u16.to_be_bytes());
    encode_dns_name(&mut request, key_name)?;
    push_u16(&mut request, 250);
    push_u16(&mut request, 255);
    push_u32(&mut request, 0);
    let rdlength_at = request.len();
    push_u16(&mut request, 0);
    let rdata_start = request.len();
    encode_dns_name(&mut request, TSIG_ALGORITHM)?;
    push_u48(&mut request, signed_at);
    push_u16(&mut request, TSIG_FUDGE_SECONDS);
    push_u16(&mut request, mac.len() as u16);
    request.extend_from_slice(&mac);
    push_u16(&mut request, id);
    push_u16(&mut request, 0);
    push_u16(&mut request, 0);
    let rdlength = request.len() - rdata_start;
    request[rdlength_at..rdlength_at + 2].copy_from_slice(&(rdlength as u16).to_be_bytes());
    Ok((request, mac))
}

struct ParsedTsig {
    message_without_tsig: Vec<u8>,
    owner: String,
    algorithm: String,
    signed_at: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    other: Vec<u8>,
}

/// 业务作用：验证 RFC2136 响应与本请求属于同一认证链，拒绝未签名或被篡改的伪成功。
///
/// 参数说明：
/// - `response`：单个有界 TCP DNS 响应 message。
/// - `id`：必须匹配的当前请求标识。
/// - `key_name`：当前请求使用的 TSIG 密钥名称。
/// - `secret`：当前请求使用的 TSIG 密钥材料。
/// - `request_mac`：用于响应认证链的当前请求 MAC。
///
/// 返回：协议头、TSIG 元数据、时间窗和 HMAC 全部合法且 rcode=NOERROR 时成功。
fn verify_rfc2136_response(
    response: &[u8],
    id: u16,
    key_name: &str,
    secret: &[u8],
    request_mac: &[u8],
) -> Result<()> {
    anyhow::ensure!(response.len() >= 12, "RFC2136 response is truncated");
    anyhow::ensure!(
        read_u16(response, 0)? == id,
        "RFC2136 response transaction id mismatch"
    );
    let flags = read_u16(response, 2)?;
    anyhow::ensure!(
        flags & 0x8000 != 0 && (flags >> 11) & 0x0f == 5,
        "RFC2136 response opcode is invalid"
    );
    let parsed = parse_response_tsig(response)?;
    anyhow::ensure!(
        parsed.owner == key_name,
        "RFC2136 response TSIG key name mismatch"
    );
    anyhow::ensure!(
        parsed.algorithm == TSIG_ALGORITHM,
        "RFC2136 response TSIG algorithm mismatch"
    );
    anyhow::ensure!(
        parsed.original_id == id,
        "RFC2136 response TSIG original id mismatch"
    );
    anyhow::ensure!(
        parsed.error == 0,
        "RFC2136 response TSIG error {}",
        parsed.error
    );
    anyhow::ensure!(
        parsed.fudge <= TSIG_FUDGE_SECONDS,
        "RFC2136 response TSIG fudge exceeds policy"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    anyhow::ensure!(
        now.abs_diff(parsed.signed_at) <= u64::from(parsed.fudge),
        "RFC2136 response TSIG time is outside allowed skew"
    );
    let mut input = Vec::with_capacity(parsed.message_without_tsig.len() + 256);
    push_u16(&mut input, request_mac.len() as u16);
    input.extend_from_slice(request_mac);
    input.extend_from_slice(&parsed.message_without_tsig);
    append_tsig_variables(
        &mut input,
        &parsed.owner,
        &parsed.algorithm,
        parsed.signed_at,
        parsed.fudge,
        parsed.error,
        &parsed.other,
    )?;
    let mut verifier =
        HmacSha256::new_from_slice(secret).context("initialize RFC2136 TSIG verifier")?;
    verifier.update(&input);
    verifier
        .verify_slice(&parsed.mac)
        .context("RFC2136 response TSIG MAC mismatch")?;
    let rcode = flags & 0x000f;
    anyhow::ensure!(rcode == 0, "RFC2136 authority returned rcode {rcode}");
    Ok(())
}

/// 业务作用：定位且拆除 DNS additional 尾部 TSIG RR，保留规范要求的待验签 message。
///
/// 参数说明：
/// - `message`：是已通过 TCP 长度门的 DNS response。
///
/// 返回：唯一末尾 TSIG 与解码字段；缺失、压缩越界或附加尾随 RR 均失败。
fn parse_response_tsig(message: &[u8]) -> Result<ParsedTsig> {
    let qd = read_u16(message, 4)? as usize;
    let an = read_u16(message, 6)? as usize;
    let ns = read_u16(message, 8)? as usize;
    let ar = read_u16(message, 10)? as usize;
    anyhow::ensure!(ar > 0, "RFC2136 response has no TSIG");
    let mut offset = 12;
    for _ in 0..qd {
        offset = skip_dns_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .context("DNS question offset overflow")?;
        anyhow::ensure!(offset <= message.len(), "DNS question is truncated");
    }
    for _ in 0..an.saturating_add(ns) {
        offset = skip_dns_rr(message, offset)?;
    }
    for index in 0..ar {
        let rr_start = offset;
        let (owner, name_end) = decode_dns_name(message, offset)?;
        offset = name_end;
        anyhow::ensure!(
            offset + 10 <= message.len(),
            "DNS additional RR is truncated"
        );
        let rr_type = read_u16(message, offset)?;
        let class = read_u16(message, offset + 2)?;
        let ttl = read_u32(message, offset + 4)?;
        let rdlength = read_u16(message, offset + 8)? as usize;
        let rdata = offset + 10;
        let rr_end = rdata
            .checked_add(rdlength)
            .context("DNS RDATA offset overflow")?;
        anyhow::ensure!(rr_end <= message.len(), "DNS additional RDATA is truncated");
        offset = rr_end;
        if rr_type != 250 {
            continue;
        }
        anyhow::ensure!(
            index + 1 == ar && rr_end == message.len(),
            "RFC2136 TSIG must be the final RR"
        );
        anyhow::ensure!(
            class == 255 && ttl == 0,
            "RFC2136 TSIG class/TTL is invalid"
        );
        let (algorithm, mut cursor) = decode_dns_name(message, rdata)?;
        anyhow::ensure!(cursor + 10 <= rr_end, "RFC2136 TSIG RDATA is truncated");
        let signed_at = read_u48(message, cursor)?;
        cursor += 6;
        let fudge = read_u16(message, cursor)?;
        cursor += 2;
        let mac_len = read_u16(message, cursor)? as usize;
        cursor += 2;
        anyhow::ensure!(
            (16..=64).contains(&mac_len) && cursor + mac_len + 6 <= rr_end,
            "RFC2136 TSIG MAC length is invalid"
        );
        let mac = message[cursor..cursor + mac_len].to_vec();
        cursor += mac_len;
        let original_id = read_u16(message, cursor)?;
        let error = read_u16(message, cursor + 2)?;
        let other_len = read_u16(message, cursor + 4)? as usize;
        cursor += 6;
        anyhow::ensure!(
            cursor + other_len == rr_end,
            "RFC2136 TSIG other data length mismatch"
        );
        let other = message[cursor..rr_end].to_vec();
        let mut message_without_tsig = message[..rr_start].to_vec();
        message_without_tsig[10..12].copy_from_slice(&((ar - 1) as u16).to_be_bytes());
        return Ok(ParsedTsig {
            message_without_tsig,
            owner,
            algorithm,
            signed_at,
            fudge,
            mac,
            original_id,
            error,
            other,
        });
    }
    anyhow::bail!("RFC2136 response has no TSIG RR")
}

/// 业务作用：按 TSIG 合同追加规范化签名变量，使 DNS 更新认证覆盖时间与密钥身份。
fn append_tsig_variables(
    output: &mut Vec<u8>,
    key_name: &str,
    algorithm: &str,
    signed_at: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Result<()> {
    encode_dns_name(output, key_name)?;
    push_u16(output, 255);
    push_u32(output, 0);
    encode_dns_name(output, algorithm)?;
    push_u48(output, signed_at);
    push_u16(output, fudge);
    push_u16(output, error);
    push_u16(output, other.len() as u16);
    output.extend_from_slice(other);
    Ok(())
}

/// 业务作用：规范 DNS 名称的 wire 表示，避免签名与发送采用不同大小写或结尾规则。
fn normalize_dns_wire_name(raw: &str) -> Result<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            }),
        "invalid DNS name"
    );
    Ok(name)
}

/// 业务作用：按 DNS label 格式编码已验证名称，不允许超长 label 或非法名称进入报文。
fn encode_dns_name(output: &mut Vec<u8>, raw: &str) -> Result<()> {
    let name = normalize_dns_wire_name(raw)?;
    for label in name.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

/// 业务作用：读取 DNS 名称并处理压缩边界，循环或越界指针必须拒绝。
fn decode_dns_name(message: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    for _ in 0..128 {
        let length = *message.get(cursor).context("DNS name is truncated")?;
        if length & 0xc0 == 0xc0 {
            let low = *message
                .get(cursor + 1)
                .context("DNS compression pointer is truncated")?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
            anyhow::ensure!(
                target < message.len(),
                "DNS compression pointer is out of bounds"
            );
            next.get_or_insert(cursor + 2);
            cursor = target;
            continue;
        }
        anyhow::ensure!(length & 0xc0 == 0, "DNS label type is unsupported");
        cursor += 1;
        if length == 0 {
            let end = next.unwrap_or(cursor);
            return Ok((labels.join(".").to_ascii_lowercase(), end));
        }
        let end = cursor + usize::from(length);
        anyhow::ensure!(length <= 63 && end <= message.len(), "DNS label is invalid");
        let label = std::str::from_utf8(&message[cursor..end]).context("DNS label is not UTF-8")?;
        labels.push(label);
        anyhow::ensure!(labels.len() <= 127, "DNS name has too many labels");
        cursor = end;
    }
    anyhow::bail!("DNS compression pointer loop")
}

/// 业务作用：安全跳过当前 DNS 名称，保留后续资源记录的准确读取位置。
fn skip_dns_name(message: &[u8], offset: usize) -> Result<usize> {
    decode_dns_name(message, offset).map(|(_, end)| end)
}

/// 业务作用：按资源记录的名称和长度跳过字段，拒绝截断的 DNS 响应。
fn skip_dns_rr(message: &[u8], offset: usize) -> Result<usize> {
    let offset = skip_dns_name(message, offset)?;
    anyhow::ensure!(offset + 10 <= message.len(), "DNS RR is truncated");
    let length = read_u16(message, offset + 8)? as usize;
    let end = offset + 10 + length;
    anyhow::ensure!(end <= message.len(), "DNS RR RDATA is truncated");
    Ok(end)
}

/// 业务作用：读取 DNS 网络序短整数，截断时返回协议错误。
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let data: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("binary u16 is truncated")?
        .try_into()
        .expect("slice length was checked");
    Ok(u16::from_be_bytes(data))
}

/// 业务作用：读取 DNS 网络序长度或 TTL 字段，不允许越过当前响应边界。
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let data: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("binary u32 is truncated")?
        .try_into()
        .expect("slice length was checked");
    Ok(u32::from_be_bytes(data))
}

/// 业务作用：读取 TSIG 的 48 位时间字段，保持协议规定的字节序。
fn read_u48(bytes: &[u8], offset: usize) -> Result<u64> {
    let data = bytes
        .get(offset..offset + 6)
        .context("binary u48 is truncated")?;
    Ok(data
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
}

/// 业务作用：按网络序编码 DNS 短整数，供记录头与长度字段共享格式。
fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// 业务作用：按网络序编码 DNS TTL 和长度值，避免依赖宿主机字节序。
fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// 业务作用：按 TSIG 规定编码签名时间，保证请求认证的时间表示一致。
fn push_u48(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes()[2..]);
}

/// 一个 ACME order 已发布的 DNS TXT 集合。
///
/// 正常路径显式 await cleanup；错误或 task cancel 时 Drop 在当前 runtime 启动 best-effort 清理，避免 TXT
/// 长期残留。provider cleanup 必须幂等，所以显式与兜底清理可安全重叠。
struct Dns01ChallengeLease {
    provider: Arc<dyn Dns01Provider>,
    records: Vec<(String, String)>,
}

impl Dns01ChallengeLease {
    /// 业务作用：创建空 DNS 租约。
    fn new(provider: Arc<dyn Dns01Provider>) -> Self {
        Self {
            provider,
            records: Vec::new(),
        }
    }

    /// 业务作用：发布成功后登记，以便任何退出路径清理。
    async fn present(&mut self, record: String, value: String) -> Result<()> {
        self.provider.present(&record, &value).await?;
        self.records.push((record, value));
        Ok(())
    }

    /// 业务作用：显式清理全部记录并返回首个错误；其余记录仍尽力清理。
    async fn cleanup_all(&mut self) -> Result<()> {
        let records = std::mem::take(&mut self.records);
        let mut first_error = None;
        for (record, value) in records {
            if let Err(error) = self.provider.cleanup(&record, &value).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Dns01ChallengeLease {
    /// 业务作用：在签发任务取消时调度尚存 DNS challenge 的清理，只处理本租约创建的记录。
    fn drop(&mut self) {
        if self.records.is_empty() {
            return;
        }
        let records = std::mem::take(&mut self.records);
        let provider = self.provider.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for (record, value) in records {
                    if let Err(error) = provider.cleanup(&record, &value).await {
                        tracing::warn!(error = %error, record = %record, "ACME DNS-01 cancel cleanup failed");
                    }
                }
            });
        }
    }
}

/// prepare 阶段已完成 provider 与分布式锁初始化、尚未产生后台副作用的 ACME worker 集。
pub struct PreparedAcmeWorkers {
    workers: Vec<PreparedAcmeWorker>,
    http01: Arc<Http01ChallengeStore>,
}

struct PreparedAcmeWorker {
    tls: TlsRuntimeCfg,
    acme: AcmeRuntimeCfg,
    lock: AcmeLockBackend,
    dns01: Option<Arc<dyn Dns01Provider>>,
}

/// 已激活 ACME worker generation；释放 generation 会协作取消仍在执行的签发/续期。
pub struct AcmeWorkerGeneration {
    stop: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl PreparedAcmeWorkers {
    /// 业务作用：激活已经完整 prepare 的 ACME worker，并把整代任务收口到同一个取消权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回持有停止权和任务句柄的 active generation；本步骤不再执行可失败的外部初始化。
    pub fn activate(self) -> AcmeWorkerGeneration {
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::with_capacity(self.workers.len());
        for worker in self.workers {
            let http01 = self.http01.clone();
            let shutdown = stop_rx.clone();
            tasks.push(tokio::spawn(async move {
                run_acme_worker(
                    worker.tls,
                    worker.acme,
                    worker.lock,
                    http01,
                    worker.dns01,
                    shutdown,
                )
                .await;
            }));
        }
        AcmeWorkerGeneration {
            stop,
            tasks,
        }
    }

    /// 业务作用：报告候选 generation 将启动的唯一证书 worker 数，用于启动与换代观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按 cert_file 去重后的 worker 数。
    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// 业务作用：判断候选 generation 是否无需启动签发任务，供调用方避免无意义观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有任何唯一证书目标时返回 true。
    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }
}

impl AcmeWorkerGeneration {
    /// 业务作用：报告当前 generation 持有的 ACME worker 数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍受本 generation 停止权管理的任务句柄数。
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// 业务作用：判断 active generation 是否没有任何签发任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：任务句柄为空时返回 true。
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// 业务作用：协作停止本代全部 ACME worker，触发 HTTP-01/DNS-01 lease 的取消清理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；任务在各自 select 边界退出，重复停止保持幂等。
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for AcmeWorkerGeneration {
    /// 业务作用：确保 generation 被热换或进程停机释放时不会遗留无主签发 worker。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；只发送取消事实，不在 Drop 中阻塞等待网络任务。
    fn drop(&mut self) {
        self.stop();
    }
}

/// 业务作用：在 listener reload 的 prepare 阶段校验并初始化完整 ACME worker 候选，不启动签发副作用。
///
/// 参数说明：
/// - `tls_configs`：是候选快照的 TLS 集
/// - `runtime_state`：提供可选 Redis 锁连接
/// - `http01`：是共享 challenge 表。
///
/// 返回：全部 provider/锁初始化成功时返回可激活候选；冲突目标、provider 或锁失败时拒绝候选并保留旧代。
pub async fn prepare_acme_workers(
    tls_configs: impl IntoIterator<Item = TlsRuntimeCfg>,
    runtime_state: crate::config::model::RuntimeStateCfg,
    http01: Arc<Http01ChallengeStore>,
) -> Result<PreparedAcmeWorkers> {
    let mut seen_cert_files = HashMap::new();
    let mut workers = Vec::new();
    for tls in tls_configs {
        let Some(acme) = tls.acme.clone() else {
            continue;
        };
        if let Some((key_file, previous)) = seen_cert_files.get(&tls.cert_file) {
            if key_file != &tls.key_file || previous != &acme {
                anyhow::bail!(
                    "conflicting ACME configs share cert target {}",
                    tls.cert_file.display()
                );
            }
            // 多个 listener 完全共享同一 keypair/config 时只需一个 signer worker。
            continue;
        }
        seen_cert_files.insert(tls.cert_file.clone(), (tls.key_file.clone(), acme.clone()));
        let dns01 = build_dns01_provider(&acme).with_context(|| {
            format!(
                "initialize ACME DNS-01 provider for {}",
                tls.cert_file.display()
            )
        })?;
        workers.push((tls, acme, dns01));
    }

    let mut prepared = Vec::with_capacity(workers.len());
    for (tls, acme, dns01) in workers {
        // 分布式互斥是签发权威；必须在快照发布前建连复验，不能先上线再让 worker 静默缺席。
        let lock = build_lock_backend(&acme, &runtime_state)
            .await
            .with_context(|| {
                format!(
                    "initialize ACME lock backend for {}",
                    tls.cert_file.display()
                )
            })?;
        prepared.push(PreparedAcmeWorker {
            tls,
            acme,
            lock,
            dns01,
        });
    }
    Ok(PreparedAcmeWorkers {
        workers: prepared,
        http01,
    })
}

/// 业务作用：在 worker prepare 阶段验证并构建 DNS-01 provider，避免快照发布后才发现命令不可执行。
///
/// 参数说明：
/// - `acme`：是已经完成语义校验的 challenge 运行配置。
///
/// 返回：HTTP-01 返回 None；DNS-01 返回可调用 provider；文件或权限不满足时拒绝候选。
fn build_dns01_provider(acme: &AcmeRuntimeCfg) -> Result<Option<Arc<dyn Dns01Provider>>> {
    match acme.challenge {
        AcmeChallenge::Http01 => Ok(None),
        AcmeChallenge::Dns01 => {
            let cfg = acme
                .dns01
                .clone()
                .context("DNS-01 runtime config is missing")?;
            let timeout = Duration::from_millis(cfg.timeout_ms);
            let retry_backoff = Duration::from_millis(cfg.retry_backoff_ms);
            let http_limits = HttpDns01Limits {
                timeout,
                retry_attempts: cfg.retry_attempts,
                retry_backoff,
                max_response_bytes: cfg.max_response_bytes,
                ttl_seconds: cfg.ttl_seconds,
            };
            let provider: Arc<dyn Dns01Provider> = match cfg.provider {
                AcmeDns01ProviderRuntime::Command {
                    command,
                    args,
                } => {
                    if !command.is_file() {
                        anyhow::bail!(
                            "DNS-01 provider command does not exist: {}",
                            command.display()
                        );
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = std::fs::metadata(&command)
                            .with_context(|| {
                                format!("stat DNS-01 provider command {}", command.display())
                            })?
                            .permissions()
                            .mode();
                        anyhow::ensure!(
                            mode & 0o111 != 0,
                            "DNS-01 provider command is not executable: {}",
                            command.display()
                        );
                    }
                    Arc::new(CommandDns01Provider {
                        command,
                        args,
                        timeout,
                    })
                }
                AcmeDns01ProviderRuntime::Cloudflare {
                    api_base,
                    zone_id,
                    api_token,
                } => Arc::new(CloudflareDns01Provider {
                    client: dns01_http_client(timeout)?,
                    api_base,
                    zone_id,
                    api_token,
                    limits: http_limits,
                    record_ids: std::sync::Mutex::new(HashMap::new()),
                }),
                AcmeDns01ProviderRuntime::Rfc2136 {
                    server,
                    zone,
                    tsig_key_name,
                    tsig_secret,
                } => Arc::new(Rfc2136Dns01Provider {
                    server,
                    zone,
                    tsig_key_name,
                    tsig_secret,
                    ttl_seconds: cfg.ttl_seconds,
                    timeout,
                    retry_attempts: cfg.retry_attempts,
                    retry_backoff,
                }),
                AcmeDns01ProviderRuntime::Vault {
                    endpoint,
                    token,
                    namespace,
                    present_path,
                    cleanup_path,
                } => Arc::new(VaultDns01Provider {
                    client: dns01_http_client(timeout)?,
                    endpoint,
                    token,
                    namespace,
                    present_path,
                    cleanup_path,
                    limits: http_limits,
                }),
            };
            Ok(Some(provider))
        }
    }
}

/// 业务作用：构造不跟随重定向的 DNS provider HTTPS 客户端，固定凭据只能送往配置 authority。
///
/// 参数说明：
/// - `timeout`：是单次 provider 操作的总上限。
///
/// 返回：TLS/连接池参数可构建时返回客户端；本步骤不发网络请求，也不产生外部副作用。
fn dns01_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .pool_max_idle_per_host(2)
        .build()
        .context("build ACME DNS provider HTTPS client")
}

/// 业务作用：在 worker prepare 阶段构造单机或 Redis 签发锁，确保候选发布前已具备唯一签发权威。
///
/// 参数说明：
/// - `acme`：是已校验 lock/storage 模式
/// - `runtime_state`：提供 Redis 连接配置。
///
/// 返回：返回可覆盖整个 order 的锁后端；feature、profile、连接或配置不满足时拒绝候选。
async fn build_lock_backend(
    acme: &AcmeRuntimeCfg,
    runtime_state: &crate::config::model::RuntimeStateCfg,
) -> Result<AcmeLockBackend> {
    if acme.lock_backend == "local" {
        return Ok(AcmeLockBackend::Local(Arc::new(
            tokio::sync::Mutex::new(()),
        )));
    }
    #[cfg(not(feature = "redis-runtime"))]
    let _ = runtime_state;
    #[cfg(feature = "redis-runtime")]
    {
        use nasa::redis::{CompatibilityProfile, DistributedLock, RedisClient, RedisConfig};

        let redis = &runtime_state.rate_limiter.redis;
        if redis.url.trim().is_empty() {
            anyhow::bail!("ACME lock_backend=redis requires runtime_state.rate_limiter.redis.url");
        }
        let profile = match redis.profile.trim() {
            "RustV2" | "rustv2" | "rust-v2" => CompatibilityProfile::RustV2,
            "LegacyV1" | "legacyv1" | "legacy-v1" => CompatibilityProfile::LegacyV1,
            other => anyhow::bail!("unsupported ACME Redis profile `{other}`"),
        };
        let client = RedisClient::connect(RedisConfig::new(
            redis.url.clone(),
            redis.namespace.clone(),
            profile,
        ))
        .await
        .context("connect Redis ACME lock through nasa::redis")?;
        Ok(AcmeLockBackend::Redis(Arc::new(DistributedLock::new(
            client,
        ))))
    }
    #[cfg(not(feature = "redis-runtime"))]
    anyhow::bail!("ACME lock_backend=redis requires gateway feature `redis-runtime`")
}

/// 业务作用：运行单个证书目标的检查/续期循环，并在 generation 失权时立即取消在途 order 或退避。
///
/// 参数说明：
/// - `tls`：指定材料路径
/// - `acme`：描述目录、域名和调度
/// - `lock`：是签发权威
/// - `http01`：发布 challenge
/// - `dns01`：发布 challenge
/// - `shutdown`：表示本 worker generation 已失权。
///
/// 返回：无业务返回；收到取消或 channel 关闭时退出，普通签发失败按有界退避继续且保留旧证书。
async fn run_acme_worker(
    tls: TlsRuntimeCfg,
    acme: AcmeRuntimeCfg,
    lock: AcmeLockBackend,
    http01: Arc<Http01ChallengeStore>,
    dns01: Option<Arc<dyn Dns01Provider>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let cycle = async {
            let tls_for_expiry = tls.clone();
            let renew_before_days = acme.renew_before_days;
            let due = tokio::task::spawn_blocking(move || {
                certificate_needs_renewal(&tls_for_expiry, renew_before_days)
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
            let delay_ms = match due {
                Ok(false) => acme.check_interval_ms,
                Ok(true) => {
                    match issue_with_lock(&tls, &acme, &lock, http01.clone(), dns01.clone()).await {
                        Ok(true) => {
                            tracing::info!(cert = %tls.cert_file.display(), domains = ?acme.domains, "ACME certificate issued and installed");
                            acme.check_interval_ms
                        }
                        Ok(false) => {
                            tracing::debug!(cert = %tls.cert_file.display(), "ACME renewal skipped: another node holds leader lock");
                            acme.retry_backoff_ms
                        }
                        Err(error) => {
                            tracing::warn!(error = %format!("{error:#}"), cert = %tls.cert_file.display(), "ACME issue/renew failed; keeping current certificate");
                            acme.retry_backoff_ms
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), cert = %tls.cert_file.display(), "ACME certificate expiry check failed");
                    acme.retry_backoff_ms
                }
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        };
        // 失去 generation 权威必须立即取消当前 order/sleep；lease Drop 会撤下已发布 challenge，
        // 防止旧配置继续写证书或留下 DNS/HTTP 临时事实。
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = cycle => {}
        }
    }
}

/// 业务作用：在互斥锁内二次检查到期状态并执行一个 ACME order。
///
/// 参数说明：
/// - `tls`: 证书输出与校验配置。
/// - `acme`: ACME order 配置。
/// - `lock`: 已初始化的互斥后端。
/// - `http01`: challenge 发布表。
/// - `dns01`：已校验的可选 DNS-01 challenge 操作计划。
///
/// 返回：本节点获得锁并完成签发为 true；未获得 Redis leader 锁为 false；其它失败返回错误。
async fn issue_with_lock(
    tls: &TlsRuntimeCfg,
    acme: &AcmeRuntimeCfg,
    lock: &AcmeLockBackend,
    http01: Arc<Http01ChallengeStore>,
    dns01: Option<Arc<dyn Dns01Provider>>,
) -> Result<bool> {
    match lock {
        AcmeLockBackend::Local(lock) => {
            let _guard = lock.clone().lock_owned().await;
            if !certificate_needs_renewal(tls, acme.renew_before_days)? {
                return Ok(true);
            }
            issue_certificate(tls, acme, http01, dns01).await?;
            Ok(true)
        }
        #[cfg(feature = "redis-runtime")]
        AcmeLockBackend::Redis(lock) => {
            let lock_key = acme_lock_key(acme);
            let Some(guard) = lock
                .try_lock(&lock_key)
                .await
                .context("acquire Redis ACME leader lock")?
            else {
                return Ok(false);
            };
            if certificate_needs_renewal(tls, acme.renew_before_days)? {
                let result = issue_certificate(tls, acme, http01, dns01).await;
                // 显式 unlock 缩短换主等待；失败仍由租约 TTL 兜底，并保留原签发结果错误。
                if let Err(error) = guard.unlock().await {
                    tracing::warn!(error = %error, "release Redis ACME leader lock failed; lease will expire");
                }
                result?;
            } else if let Err(error) = guard.unlock().await {
                tracing::warn!(error = %error, "release unused Redis ACME leader lock failed");
            }
            Ok(true)
        }
    }
}

/// 业务作用：构造包含域名集合的锁 key，避免同集群不同证书目标互相阻塞。
///
/// 参数说明：
/// - `acme`: 已规范化域名与用户配置的锁前缀。
///
/// 返回：稳定、可读的 Redis 业务锁 key；只在低频续期控制面分配。
#[cfg(feature = "redis-runtime")]
fn acme_lock_key(acme: &AcmeRuntimeCfg) -> String {
    format!("{}:{}", acme.lock_key, acme.domains.join(","))
}

/// 业务作用：执行完整 HTTP-01 或 DNS-01 order，并把新 keypair 安装到 TLS watcher 的事实源路径。
///
/// 参数说明：
/// - `tls`: 最终 cert/key 文件位置。
/// - `acme`: 目录、SAN、账户与轮询策略。
/// - `http01`: 请求数据面读取的 challenge 表。
/// - `dns01`: DNS-01 provider；HTTP-01 时为空。
async fn issue_certificate(
    tls: &TlsRuntimeCfg,
    acme: &AcmeRuntimeCfg,
    http01: Arc<Http01ChallengeStore>,
    dns01: Option<Arc<dyn Dns01Provider>>,
) -> Result<()> {
    let account = load_or_create_account(acme).await?;
    let identifiers = acme
        .domains
        .iter()
        .cloned()
        .map(Identifier::Dns)
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("create ACME order")?;
    let mut http_lease = Http01ChallengeLease::new(http01);
    let mut dns_lease = dns01.map(Dns01ChallengeLease::new);
    {
        // authorization iterator 借用 order；限制在该作用域，之后才能继续 poll/finalize。
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result.context("load ACME authorization")?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => anyhow::bail!("unexpected ACME authorization status: {status:?}"),
            }
            let challenge_type = match acme.challenge {
                AcmeChallenge::Http01 => ChallengeType::Http01,
                AcmeChallenge::Dns01 => ChallengeType::Dns01,
            };
            let mut challenge =
                authorization
                    .challenge(challenge_type.clone())
                    .ok_or_else(|| {
                        anyhow::anyhow!("ACME server offered no {challenge_type:?} challenge")
                    })?;
            match acme.challenge {
                AcmeChallenge::Http01 => {
                    let key_authorization = challenge.key_authorization();
                    http_lease.insert(&challenge.token, key_authorization.as_str())?;
                }
                AcmeChallenge::Dns01 => {
                    let identifier = match challenge.identifier().identifier {
                        Identifier::Dns(domain) => domain.as_str(),
                        other => anyhow::bail!(
                            "DNS-01 provider only supports DNS identifiers; got {other:?}"
                        ),
                    };
                    let record = format!("_acme-challenge.{identifier}");
                    let value = challenge.key_authorization().dns_value();
                    dns_lease
                        .as_mut()
                        .context("DNS-01 provider is unavailable")?
                        .present(record, value)
                        .await?;
                    let delay_ms = acme
                        .dns01
                        .as_ref()
                        .context("DNS-01 runtime config is missing")?
                        .propagation_delay_ms;
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
            challenge
                .set_ready()
                .await
                .with_context(|| format!("mark {challenge_type:?} challenge ready"))?;
        }
    }
    let retry = RetryPolicy::new().timeout(Duration::from_millis(acme.order_timeout_ms));
    let status_result = order
        .poll_ready(&retry)
        .await
        .context("poll ACME order ready");
    // CA 完成 challenge 校验后立即撤下 HTTP/DNS 临时事实；cleanup 失败不能静默留下长期 TXT。
    drop(http_lease);
    let cleanup_result = match dns_lease.as_mut() {
        Some(lease) => lease
            .cleanup_all()
            .await
            .context("cleanup ACME DNS-01 records"),
        None => Ok(()),
    };
    let status = status_result?;
    cleanup_result?;
    if status != OrderStatus::Ready {
        anyhow::bail!("ACME order did not become ready: {status:?}");
    }
    let private_key_pem = order.finalize().await.context("finalize ACME order")?;
    let certificate_pem = order
        .poll_certificate(&retry)
        .await
        .context("download ACME certificate")?;
    let tls = tls.clone();
    tokio::task::spawn_blocking(move || {
        install_keypair_atomically(&tls, certificate_pem.as_bytes(), private_key_pem.as_bytes())
    })
    .await
    .context("join ACME keypair installer")??;
    Ok(())
}

/// 业务作用：从 SecretSource 文件恢复 ACME 账户；首次使用时创建并以 0600 原子持久化凭据。
///
/// 参数说明：
/// - `acme`: directory/contact/account 文件配置。
///
/// 返回：可创建 order 的账户。损坏凭据不会被覆盖，而是失败保留供人工恢复。
async fn load_or_create_account(acme: &AcmeRuntimeCfg) -> Result<Account> {
    let account_file = acme.account_credentials_file.clone();
    let existing = tokio::task::spawn_blocking(move || {
        crate::io::bounded_io::read_optional_file(
            &account_file,
            MAX_ACME_ACCOUNT_CREDENTIAL_BYTES,
            "ACME account credentials",
        )
    })
    .await
    .context("join ACME account credential reader")??;
    match existing {
        Some(bytes) => {
            let credentials = serde_json::from_slice::<AccountCredentials>(&bytes)
                .context("parse ACME account credentials secret")?;
            account_builder(acme)?
                .from_credentials(credentials)
                .await
                .context("restore ACME account credentials")
        }
        None => {
            let contacts = acme.contacts.iter().map(String::as_str).collect::<Vec<_>>();
            let (account, credentials) = account_builder(acme)?
                .create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    acme.directory_url.clone(),
                    None,
                )
                .await
                .context("create ACME account")?;
            let secret = serde_json::to_vec(&credentials).context("serialize ACME credentials")?;
            anyhow::ensure!(
                secret.len() <= MAX_ACME_ACCOUNT_CREDENTIAL_BYTES,
                "serialized ACME account credentials exceed {MAX_ACME_ACCOUNT_CREDENTIAL_BYTES} bytes"
            );
            let path = acme.account_credentials_file.clone();
            tokio::task::spawn_blocking(move || atomic_write(&path, &secret, true))
                .await
                .context("join ACME account secret writer")??;
            Ok(account)
        }
    }
}

/// 业务作用：构造与 gateway rustls provider 一致的 instant-acme 账户 builder。
///
/// 参数说明：
/// - `acme`: 可选私有 ACME directory 根 CA；未配置时使用系统平台根证书。
///
/// 返回：使用平台根或显式单一测试/企业根 CA，以及 aws-lc-rs 签名实现的 builder。
fn account_builder(acme: &AcmeRuntimeCfg) -> Result<AccountBuilder> {
    match &acme.directory_ca_file {
        Some(path) => Account::builder_with_root(path)
            .with_context(|| format!("build ACME account client with CA {}", path.display())),
        None => Account::builder().context("build ACME account client"),
    }
}

/// 业务作用：判断现有 PEM 证书是否进入续期窗口；文件不存在视为需要签发。
///
/// 参数说明：
/// - `tls`: TLS 默认 pair 与可选 manifest 指针。
/// - `renew_before_days`: 到期前续期窗口。
///
/// 返回：缺失或 `notAfter <= now + window` 为 true；PEM/X.509 损坏返回错误，不盲目覆盖证据。
fn certificate_needs_renewal(tls: &TlsRuntimeCfg, renew_before_days: u64) -> Result<bool> {
    let (cert_file, _) = crate::tls::active_keypair_paths(tls)?;
    let bytes = match crate::io::bounded_io::read_optional_file(
        &cert_file,
        MAX_ACME_CERTIFICATE_BYTES,
        "ACME certificate",
    )? {
        Some(bytes) => bytes,
        None => return Ok(true),
    };
    let mut reader = Cursor::new(bytes);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse ACME leaf certificate PEM")?
        .ok_or_else(|| anyhow::anyhow!("certificate PEM contains no certificate"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parse ACME leaf X.509: {error}"))?;
    let not_after = certificate.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64;
    let renew_window = renew_before_days
        .saturating_mul(86_400)
        .min(i64::MAX as u64) as i64;
    Ok(not_after <= now.saturating_add(renew_window))
}

/// 业务作用：串行化 ACME/自动续期的证书安装，避免同一进程内两个完整 pair 交错发布。
///
/// 参数说明：
/// - `tls`：定位事实源
/// - `certificate_pem`：是完整证书链
/// - `private_key_pem`：是匹配私钥。
///
/// 返回：pair 通过密码学校验并完整发布时成功；锁、校验或 I/O 失败时返回错误且不得宣告换版。
pub(crate) fn install_keypair_atomically(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)?;
    install_keypair_atomically_locked(tls, certificate_pem, private_key_pem)
}

/// 手工证书 CAS 安装结果。
pub(crate) enum KeypairCasInstallOutcome {
    /// 比较基线仍一致，完整 pair 已发布。
    Installed,
    /// 安装前证书已变化，未写入任何文件。
    Changed(String),
}

/// 业务作用：在与 ACME 续期共享的进程锁内复验证书摘要并安装完整 pair，防止 Console 覆盖刚完成
/// 的自动续期。
///
/// 参数说明：
/// - `tls`：固定当前证书事实源的 TLS 策略。
/// - `expected_etag`：从证书读取接口取得的 CAS 基线 ETag。
/// - `certificate_pem`：有界上传的完整证书 PEM。
/// - `private_key_pem`：有界上传的完整私钥 PEM。
///
/// 返回：基线一致且 pair 合法时返回 Installed；摘要变化返回当前 ETag 且无副作用；读取、校验或落盘
/// 失败返回错误。
pub(crate) fn install_keypair_atomically_if_match(
    tls: &TlsRuntimeCfg,
    expected_etag: &str,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<KeypairCasInstallOutcome> {
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)?;
    let (certificate_path, _) = crate::tls::active_keypair_paths_unrecovered(tls)?;
    let current = crate::io::bounded_io::read_file(
        &certificate_path,
        MAX_ACME_CERTIFICATE_BYTES,
        "TLS certificate CAS baseline",
    )?;
    let current_etag = certificate_etag(&current);
    if expected_etag.trim() != current_etag {
        return Ok(KeypairCasInstallOutcome::Changed(current_etag));
    }
    install_keypair_atomically_locked(tls, certificate_pem, private_key_pem)?;
    Ok(KeypairCasInstallOutcome::Installed)
}

/// 业务作用：返回 ACME 与手工轮换共享的证书安装互斥锁，保证比较和 manifest/pair 发布不交错。
///
/// 参数说明: 无。
///
/// 返回：返回进程生命周期内唯一互斥锁。
fn keypair_install_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// 业务作用：在任何旧双文件 pair 读取前完成上次崩溃事务恢复，使 loader 只能看到恢复后的完整代。
///
/// 参数说明：
/// - `tls`：固定 cert/key 目标；manifest 模式没有双文件事务，直接成功。
///
/// 返回：无待恢复事务或已恢复/确认提交时成功；journal 损坏或 I/O 失败时拒绝加载证书。
pub(crate) fn recover_legacy_keypair_transaction(tls: &TlsRuntimeCfg) -> Result<()> {
    if tls.keypair_manifest_file.is_some() {
        return Ok(());
    }
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    recover_legacy_keypair_transaction_locked(tls)
}

/// 业务作用：为证书原始字节生成强 ETag，供读接口与手工轮换 CAS 使用同一比较语义。
///
/// 参数说明：
/// - `certificate_pem`：是有界读取或上传的完整证书链字节。
///
/// 返回：返回带引号的 `sha256-<hex>` 强 ETag。
pub(crate) fn certificate_etag(certificate_pem: &[u8]) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(certificate_pem);
    let mut encoded = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
    }
    format!("\"sha256-{encoded}\"")
}

/// 业务作用：在调用方已持有证书安装锁时校验并发布 pair，集中维护 manifest 与兼容文件模式语义。
///
/// 参数说明：
/// - `tls`：固定安装事实源的 TLS 策略。
/// - `certificate_pem`：待校验和安装的完整证书 PEM。
/// - `private_key_pem`：待校验和安装的完整私钥 PEM。
///
/// 返回：pair 合法且事实源完整切换时成功；校验或任一步 I/O 失败时返回错误。
fn install_keypair_atomically_locked(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    validate_keypair(certificate_pem, private_key_pem)?;
    if let Some(manifest_file) = &tls.keypair_manifest_file {
        let prepared = prepare_keypair_version(manifest_file, certificate_pem, private_key_pem)?;
        atomic_write(manifest_file, &prepared.manifest, false)?;
        tracing::info!(
            directory = %prepared.directory.display(),
            manifest = %manifest_file.display(),
            "activated immutable TLS keypair version"
        );
        let retention = tls
            .acme
            .as_ref()
            .map(|acme| acme.keypair_retention_generations)
            .unwrap_or(3);
        if let Err(error) = gc_keypair_versions(manifest_file, retention) {
            // 当前 manifest 已持久化；回收失败只留下额外历史，不能谎称激活失败并诱发重复签发。
            tracing::warn!(error = %format!("{error:#}"), "TLS keypair history cleanup failed");
        }
    } else {
        install_legacy_keypair_transaction(tls, certificate_pem, private_key_pem)?;
    }
    Ok(())
}

/// 业务作用：以持久 journal 发布旧式 cert/key 双文件，并在任一步失败时恢复安装前事实。
///
/// 参数说明：
/// - `tls`：固定证书与私钥目标路径的 TLS 策略。
/// - `certificate_pem`：已经完成密钥对密码学校验的证书 PEM。
/// - `private_key_pem`：已经完成密钥对密码学校验的私钥 PEM。
///
/// 返回：两个目标均成为新代且 journal 已结算时成功；失败时先恢复旧代再返回原错误。
fn install_legacy_keypair_transaction(
    tls: &TlsRuntimeCfg,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<()> {
    recover_legacy_keypair_transaction_locked(tls)?;
    let transaction = legacy_keypair_transaction_dir(tls)?;
    let parent = transaction
        .parent()
        .context("legacy keypair transaction has no parent")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "create legacy keypair transaction parent {}",
            parent.display()
        )
    })?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate legacy keypair transaction suffix")?;
    let temporary = parent.join(format!(
        ".naway-keypair-prepare-{:016x}",
        u64::from_le_bytes(random)
    ));
    fs::create_dir(&temporary)
        .with_context(|| format!("create legacy keypair transaction {}", temporary.display()))?;
    let prepared = (|| -> Result<()> {
        let old_cert = crate::io::bounded_io::read_optional_file(
            &tls.cert_file,
            MAX_ACME_CERTIFICATE_BYTES,
            "legacy TLS certificate backup",
        )?;
        let old_key = crate::io::bounded_io::read_optional_file(
            &tls.key_file,
            MAX_ACME_CERTIFICATE_BYTES,
            "legacy TLS private key backup",
        )?;
        if let Some(bytes) = &old_cert {
            atomic_write(&temporary.join("old-cert.pem"), bytes, false)?;
        }
        if let Some(bytes) = &old_key {
            atomic_write(&temporary.join("old-key.pem"), bytes, true)?;
        }
        atomic_write(&temporary.join("new-cert.pem"), certificate_pem, false)?;
        atomic_write(&temporary.join("new-key.pem"), private_key_pem, true)?;
        atomic_write(
            &temporary.join("state.json"),
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "old_cert_present": old_cert.is_some(),
                "old_key_present": old_key.is_some(),
            }))?,
            false,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, &transaction).with_context(|| {
            format!(
                "publish legacy keypair transaction {}",
                transaction.display()
            )
        })?;
        sync_directory(parent)
    })();
    if let Err(error) = prepared {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }

    let publish = (|| -> Result<()> {
        // journal 已经持久化，两个 rename 之间即使崩溃也能在下一次读取前恢复旧代或确认新代。
        atomic_write(&tls.key_file, private_key_pem, true)?;
        atomic_write(&tls.cert_file, certificate_pem, false)?;
        Ok(())
    })();
    if let Err(error) = publish {
        recover_legacy_keypair_transaction_locked(tls)
            .context("restore legacy TLS pair after failed publish")?;
        return Err(error);
    }
    finish_legacy_keypair_transaction(&transaction)?;
    Ok(())
}

/// 业务作用：检查旧式 pair journal；完整新代已落盘则提交，否则按备份恢复安装前状态。
///
/// 参数说明：
/// - `tls`：固定 journal 身份和两个目标；调用方持有全局安装锁。
///
/// 返回：journal 不存在、确认提交或恢复完成时成功；任何不可信 journal/材料拒绝继续读取。
fn recover_legacy_keypair_transaction_locked(tls: &TlsRuntimeCfg) -> Result<()> {
    if tls.keypair_manifest_file.is_some() {
        return Ok(());
    }
    let transaction = legacy_keypair_transaction_dir(tls)?;
    let metadata = match fs::symlink_metadata(&transaction) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("stat legacy keypair transaction"),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "legacy keypair transaction path is not a directory"
    );
    let state_bytes = crate::io::bounded_io::read_file(
        &transaction.join("state.json"),
        64 * 1024,
        "legacy keypair transaction state",
    )?;
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).context("parse legacy keypair transaction state")?;
    anyhow::ensure!(
        state
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "legacy keypair transaction schema is invalid"
    );
    let old_cert_present = state
        .get("old_cert_present")
        .and_then(serde_json::Value::as_bool)
        .context("legacy keypair transaction old_cert_present is missing")?;
    let old_key_present = state
        .get("old_key_present")
        .and_then(serde_json::Value::as_bool)
        .context("legacy keypair transaction old_key_present is missing")?;
    let new_cert = crate::io::bounded_io::read_file(
        &transaction.join("new-cert.pem"),
        MAX_ACME_CERTIFICATE_BYTES,
        "legacy keypair transaction new certificate",
    )?;
    let new_key = crate::io::bounded_io::read_file(
        &transaction.join("new-key.pem"),
        MAX_ACME_CERTIFICATE_BYTES,
        "legacy keypair transaction new key",
    )?;
    validate_keypair(&new_cert, &new_key)?;
    let live_cert = crate::io::bounded_io::read_optional_file(
        &tls.cert_file,
        MAX_ACME_CERTIFICATE_BYTES,
        "legacy TLS live certificate",
    )?;
    let live_key = crate::io::bounded_io::read_optional_file(
        &tls.key_file,
        MAX_ACME_CERTIFICATE_BYTES,
        "legacy TLS live key",
    )?;
    if live_cert.as_deref() == Some(new_cert.as_slice())
        && live_key.as_deref() == Some(new_key.as_slice())
    {
        return finish_legacy_keypair_transaction(&transaction);
    }

    // 新代不完整就先恢复 secret key、再恢复证书；loader 持有同一安装锁，恢复期间不能发布中间态。
    restore_legacy_file(
        &tls.key_file,
        &transaction.join("old-key.pem"),
        old_key_present,
        true,
    )?;
    restore_legacy_file(
        &tls.cert_file,
        &transaction.join("old-cert.pem"),
        old_cert_present,
        false,
    )?;
    finish_legacy_keypair_transaction(&transaction)
}

/// 业务作用：在证书安装事务未完成时恢复单个旧文件，避免遗留新旧不配对的证书材料。
fn restore_legacy_file(target: &Path, backup: &Path, present: bool, secret: bool) -> Result<()> {
    if present {
        let bytes = crate::io::bounded_io::read_file(
            backup,
            MAX_ACME_CERTIFICATE_BYTES,
            "legacy keypair transaction backup",
        )?;
        atomic_write(target, &bytes, secret)
    } else {
        match fs::remove_file(target) {
            Ok(()) => sync_directory(target.parent().unwrap_or_else(|| Path::new("."))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("remove partial TLS file {}", target.display()))
            }
        }
    }
}

/// 业务作用：为固定证书路径定位配对安装事务目录，恢复记录不能跨目标复用。
fn legacy_keypair_transaction_dir(tls: &TlsRuntimeCfg) -> Result<PathBuf> {
    use sha2::Digest as _;
    anyhow::ensure!(
        tls.cert_file != tls.key_file,
        "TLS cert_file and key_file must differ"
    );
    let parent = tls
        .cert_file
        .parent()
        .context("TLS cert_file has no parent")?;
    let mut digest = sha2::Sha256::new();
    digest.update(tls.cert_file.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(tls.key_file.as_os_str().as_encoded_bytes());
    let encoded = digest.finalize();
    let mut suffix = String::with_capacity(24);
    use std::fmt::Write as _;
    for byte in &encoded[..12] {
        write!(&mut suffix, "{byte:02x}").expect("writing digest to String cannot fail");
    }
    Ok(parent.join(format!(".naway-keypair-transaction-{suffix}")))
}

/// 业务作用：完成或恢复证书配对事务，并在一致性确认后清理对应事务状态。
fn finish_legacy_keypair_transaction(transaction: &Path) -> Result<()> {
    fs::remove_dir_all(transaction).with_context(|| {
        format!(
            "remove legacy keypair transaction {}",
            transaction.display()
        )
    })?;
    sync_directory(transaction.parent().unwrap_or_else(|| Path::new(".")))
}

struct PreparedKeypairVersion {
    directory: PathBuf,
    manifest: Vec<u8>,
}

/// 业务作用：把完整 pair 写入不可变版本目录，但不切换当前 manifest。
///
/// 返回的 manifest 只有在调用者以单次原子 rename 安装后才生效；因此进程在本函数后
/// 崩溃只会留下无引用版本，旧 pair 仍是唯一事实。
fn prepare_keypair_version(
    manifest_file: &Path,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<PreparedKeypairVersion> {
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create keypair manifest dir {}", parent.display()))?;
    let versions_root = parent.join(".gateway-keypairs");
    fs::create_dir_all(&versions_root)
        .with_context(|| format!("create keypair versions dir {}", versions_root.display()))?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate keypair version suffix")?;
    let suffix = u64::from_le_bytes(random);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let directory = versions_root.join(format!("v-{timestamp}-{suffix:016x}"));
    fs::create_dir(&directory)
        .with_context(|| format!("create keypair version {}", directory.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod keypair version {}", directory.display()))?;
    }
    let result = (|| -> Result<Vec<u8>> {
        atomic_write(&directory.join("key.pem"), private_key_pem, true)?;
        atomic_write(&directory.join("cert.pem"), certificate_pem, false)?;
        sync_directory(&directory)?;
        let relative = directory.strip_prefix(parent).with_context(|| {
            format!(
                "keypair version {} is outside manifest dir {}",
                directory.display(),
                parent.display()
            )
        })?;
        let relative = relative
            .to_str()
            .context("keypair version path is not UTF-8")?;
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "directory": relative,
        }))
        .context("serialize keypair manifest")
    })();
    match result {
        Ok(manifest) => Ok(PreparedKeypairVersion {
            directory,
            manifest,
        }),
        Err(error) => {
            let _ = fs::remove_dir_all(&directory);
            Err(error)
        }
    }
}

/// 业务作用：按保留代数回收 manifest 历史目录，同时永久保护当前指针和崩溃遗留临时指针。
///
/// 参数说明：
/// - `manifest_file`：是唯一激活指针
/// - `retention`：是至少两代的配置硬门。
///
/// 返回：所有可安全判定的过期完整目录已删除时成功；路径、指针或目录事实不可信时停止回收。
fn gc_keypair_versions(manifest_file: &Path, retention: usize) -> Result<()> {
    anyhow::ensure!(
        (2..=64).contains(&retention),
        "TLS keypair retention is out of range"
    );
    let parent = manifest_file.parent().unwrap_or_else(|| Path::new("."));
    let root = parent.join(".gateway-keypairs");
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("stat TLS keypair versions root"),
    };
    anyhow::ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "TLS keypair versions root is not a directory"
    );
    let root_canonical =
        fs::canonicalize(&root).context("canonicalize TLS keypair versions root")?;
    let current = crate::io::bounded_io::read_file(
        manifest_file,
        64 * 1024,
        "TLS keypair manifest for cleanup",
    )?;
    let current_version = manifest_version_name(&current)?;
    let mut protected = std::collections::HashSet::new();
    protected.insert(current_version.clone());

    let manifest_name = manifest_file
        .file_name()
        .and_then(|name| name.to_str())
        .context("TLS keypair manifest file name is invalid")?;
    let temporary_prefix = format!(".{manifest_name}.tmp-");
    for entry in fs::read_dir(parent).context("scan TLS keypair manifest directory")? {
        let entry = entry.context("read TLS keypair manifest directory entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&temporary_prefix) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        if let Ok(bytes) = crate::io::bounded_io::read_file(
            &entry.path(),
            64 * 1024,
            "temporary TLS keypair manifest",
        ) {
            if let Ok(version) = manifest_version_name(&bytes) {
                protected.insert(version);
            }
        }
    }

    let mut versions = Vec::new();
    for entry in fs::read_dir(&root).context("scan TLS keypair versions")? {
        let entry = entry.context("read TLS keypair version entry")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !valid_keypair_version_name(&name) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let cert = fs::symlink_metadata(entry.path().join("cert.pem"));
        let key = fs::symlink_metadata(entry.path().join("key.pem"));
        if !matches!(cert, Ok(ref value) if value.is_file() && !value.file_type().is_symlink())
            || !matches!(key, Ok(ref value) if value.is_file() && !value.file_type().is_symlink())
        {
            continue;
        }
        versions.push((name, entry.path()));
    }
    versions.sort_by(|left, right| right.0.cmp(&left.0));
    let mut retained = std::collections::HashSet::new();
    retained.insert(current_version);
    for (name, _) in &versions {
        if retained.len() >= retention {
            break;
        }
        retained.insert(name.clone());
    }
    protected.extend(retained);
    for (name, path) in versions {
        if protected.contains(&name) {
            continue;
        }
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("canonicalize TLS keypair version {}", path.display()))?;
        anyhow::ensure!(
            canonical.parent() == Some(root_canonical.as_path()),
            "TLS keypair cleanup target escaped versions root"
        );
        fs::remove_dir_all(&canonical)
            .with_context(|| format!("remove TLS keypair history {}", canonical.display()))?;
    }
    sync_directory(&root)
}

/// 业务作用：从证书指针清单取得材料代际名称，供加载与清理定位同一版本目录。
fn manifest_version_name(bytes: &[u8]) -> Result<String> {
    let document: serde_json::Value =
        serde_json::from_slice(bytes).context("parse TLS keypair manifest for cleanup")?;
    anyhow::ensure!(
        document
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "TLS keypair cleanup manifest schema is invalid"
    );
    let directory = document
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .context("TLS keypair cleanup manifest directory is missing")?;
    let path = Path::new(directory);
    let mut components = path.components();
    anyhow::ensure!(
        matches!(components.next(), Some(std::path::Component::Normal(root)) if root == ".gateway-keypairs")
            && matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none(),
        "TLS keypair cleanup manifest directory is outside version root"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("TLS keypair cleanup manifest version name is invalid")?;
    anyhow::ensure!(
        valid_keypair_version_name(name),
        "TLS keypair cleanup manifest version name is invalid"
    );
    Ok(name.to_owned())
}

/// 业务作用：限制证书版本目录名称，禁止指针清单引导读取任意文件路径。
fn valid_keypair_version_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("v-") else {
        return false;
    };
    let Some((timestamp, suffix)) = rest.split_once('-') else {
        return false;
    };
    !timestamp.is_empty()
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.len() == 16
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 业务作用：在落盘前验证证书链可解析、私钥算法受 rustls 支持且 leaf/key 匹配。
///
/// 参数说明：
/// - `certificate_pem`: 待安装证书链。
/// - `private_key_pem`: 待安装私钥。
fn validate_keypair(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<()> {
    let mut cert_reader = Cursor::new(certificate_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse issued certificate chain")?;
    if certs.is_empty() {
        anyhow::bail!("issued certificate chain is empty");
    }
    let mut key_reader = Cursor::new(private_key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse issued private key")?
        .ok_or_else(|| anyhow::anyhow!("issued private key is empty"))?;
    let signing_key = tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .context("issued private key algorithm is unsupported")?;
    let certified = tokio_rustls::rustls::sign::CertifiedKey::new(certs, signing_key);
    certified
        .keys_match()
        .context("issued certificate does not match private key")
}

/// 业务作用：把一个文件同目录原子替换，并在 secret 模式下强制 0600 权限。
///
/// 参数说明：
/// - `path`: 最终事实源路径。
/// - `bytes`: 完整新文件内容。
/// - `secret`: true 用 0600，false 用 0644。
fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("atomic target has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create secret dir {}", parent.display()))?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate atomic file suffix")?;
    let suffix = u64::from_le_bytes(random);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("atomic target has invalid file name"))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{suffix:016x}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret {
            0o600
        } else {
            0o644
        });
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create atomic temp {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write atomic temp {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync atomic temp {}", temporary.display()))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("rename atomic target {}", path.display()))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// 业务作用：Unix 上 fsync 目录项，使 create/rename 在突然断电后也有可预期持久性。
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .with_context(|| format!("open directory for fsync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("fsync directory {}", path.display()))?;
    }
    Ok(())
}
