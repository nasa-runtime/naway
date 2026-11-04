//! ACME 证书自动化运行时：HTTP-01 临时响应与签发/续期 worker，材料交由统一安装事务发布。
//!
//! 请求热路径只在固定前缀命中后读取 challenge 表；正常业务 path 只有一次 `starts_with`，不会加锁。
//! ACME 网络交互、证书解析和文件同步全部在控制面后台任务执行。

use std::collections::HashMap;
use std::future::Future;
use std::io::Cursor;
use std::path::PathBuf;
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

use super::keypair::atomic_write;
pub(crate) use super::keypair::{
    certificate_etag, install_keypair_atomically, recover_legacy_keypair_transaction,
};
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
