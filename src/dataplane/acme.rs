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
use hyper::{Response, StatusCode};
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};

use crate::config::{AcmeChallenge, AcmeDns01RuntimeCfg, AcmeRuntimeCfg, TlsRuntimeCfg};
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
    /// 创建一个空 challenge 表。
    ///
    /// 返回：可由所有 proxy 与 ACME worker 共享的常驻句柄。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 在 ACME 验证窗口发布一个 token。
    ///
    /// # 参数
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

    /// 移除一个已完成/失败订单的 token。
    ///
    /// # 参数
    /// - `token`: 先前发布的 challenge token。
    pub fn remove(&self, token: &str) {
        self.challenges
            .write()
            .expect("ACME HTTP-01 store poisoned")
            .remove(token);
    }

    /// 尝试为当前请求构造 HTTP-01 响应。
    ///
    /// # 参数
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
    /// 为一个 ACME order 创建空租约。
    ///
    /// # 参数
    /// - `store`: 数据面正在读取的共享 HTTP-01 表。
    ///
    /// 返回：可逐个发布 token 的 RAII 租约。
    pub fn new(store: Arc<Http01ChallengeStore>) -> Self {
        Self {
            store,
            tokens: Vec::new(),
        }
    }

    /// 发布 token 并纳入自动清理集合。
    ///
    /// # 参数
    /// - `token`: ACME challenge token。
    /// - `key_authorization`: HTTP-01 响应体。
    pub fn insert(&mut self, token: &str, key_authorization: &str) -> anyhow::Result<()> {
        self.store.insert(token, key_authorization)?;
        self.tokens.push(token.to_owned());
        Ok(())
    }
}

impl Drop for Http01ChallengeLease {
    /// 订单退出时撤下全部公开 challenge，防止旧 token 长期残留。
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
    /// 发布一个 `_acme-challenge` TXT 值。
    ///
    /// # 参数
    /// - `record`: 不带尾点的完整 TXT record name。
    /// - `value`: RFC 8555 key authorization digest。
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// 清理先前发布的 TXT 值；实现必须幂等，允许错误/取消路径重复调用。
    ///
    /// # 参数
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
    cfg: AcmeDns01RuntimeCfg,
}

impl CommandDns01Provider {
    /// 执行一次有界 provider 操作。
    async fn run(&self, action: &'static str, record: &str, value: &str) -> Result<()> {
        let mut command = tokio::process::Command::new(&self.cfg.command);
        command
            .args(self.cfg.args.iter())
            .env("GW_ACME_DNS_ACTION", action)
            .env("GW_ACME_DNS_RECORD", record)
            .env("GW_ACME_DNS_VALUE", value)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let status =
            tokio::time::timeout(Duration::from_millis(self.cfg.timeout_ms), command.status())
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
    fn present<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.run("present", record, value))
    }

    fn cleanup<'a>(
        &'a self,
        record: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.run("cleanup", record, value))
    }
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
    /// 创建空 DNS 租约。
    fn new(provider: Arc<dyn Dns01Provider>) -> Self {
        Self {
            provider,
            records: Vec::new(),
        }
    }

    /// 发布成功后登记，以便任何退出路径清理。
    async fn present(&mut self, record: String, value: String) -> Result<()> {
        self.provider.present(&record, &value).await?;
        self.records.push((record, value));
        Ok(())
    }

    /// 显式清理全部记录并返回首个错误；其余记录仍尽力清理。
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

/// 启动当前初始快照中全部 ACME 续期 worker。
///
/// ACME 配置被视为 bootstrap 拓扑的一部分，运行中修改会被 reload 拒绝；这样 worker、HTTP-01 store
/// 与证书 watcher 不会出现新旧配置撕裂。相同 cert 路径只启动一个 worker。
///
/// # 参数
/// - `tls_configs`: 启动期所有 proxy TLS 配置。
/// - `runtime_state`: Redis URL/namespace/profile 来源；只有 lock_backend=redis 时使用。
/// - `http01`: 数据面正在读取的共享 challenge 表。
///
/// 返回：实际启动的 worker 数。同一 cert 目标配置冲突、Redis 锁初始化失败时返回
/// `Err` 阻止带病启动，不把“已配 ACME 但 worker 已停用”伪装成正常。
pub async fn spawn_acme_workers(
    tls_configs: impl IntoIterator<Item = TlsRuntimeCfg>,
    runtime_state: crate::config::model::RuntimeStateCfg,
    http01: Arc<Http01ChallengeStore>,
) -> Result<usize> {
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

    let mut started = 0;
    for (tls, acme, dns01) in workers {
        // 启动前先建立锁后端；分布式互斥不可用时必须 fail-fast。
        let lock = build_lock_backend(&acme, &runtime_state)
            .await
            .with_context(|| {
                format!(
                    "initialize ACME lock backend for {}",
                    tls.cert_file.display()
                )
            })?;
        let http01 = http01.clone();
        tokio::spawn(async move {
            run_acme_worker(tls, acme, lock, http01, dns01).await;
        });
        started += 1;
    }
    Ok(started)
}

/// 按已编译 challenge 配置创建 DNS provider；HTTP-01 返回 None。
fn build_dns01_provider(acme: &AcmeRuntimeCfg) -> Result<Option<Arc<dyn Dns01Provider>>> {
    match acme.challenge {
        AcmeChallenge::Http01 => Ok(None),
        AcmeChallenge::Dns01 => {
            let cfg = acme
                .dns01
                .clone()
                .context("DNS-01 runtime config is missing")?;
            if !cfg.command.is_file() {
                anyhow::bail!(
                    "DNS-01 provider command does not exist: {}",
                    cfg.command.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&cfg.command)
                    .with_context(|| {
                        format!("stat DNS-01 provider command {}", cfg.command.display())
                    })?
                    .permissions()
                    .mode();
                anyhow::ensure!(
                    mode & 0o111 != 0,
                    "DNS-01 provider command is not executable: {}",
                    cfg.command.display()
                );
            }
            Ok(Some(Arc::new(CommandDns01Provider { cfg })))
        }
    }
}

/// 构造单机或 Redis ACME 锁后端。
///
/// # 参数
/// - `acme`: 已校验 lock/storage 模式的 ACME 配置。
/// - `runtime_state`: Redis 连接配置来源。
///
/// 返回：可在整个订单期间持有的锁后端；feature/Redis 配置不满足时返回错误并禁用 worker。
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

/// 单个证书目标的长期检查/续期循环。
///
/// # 参数
/// - `tls`: 证书输出路径与 TLS watcher 使用的完整 listener 配置。
/// - `acme`: ACME 目录、域名与调度策略。
/// - `lock`: 单机或 Redis 锁后端。
/// - `http01`: HTTP-01 数据面发布表。
async fn run_acme_worker(
    tls: TlsRuntimeCfg,
    acme: AcmeRuntimeCfg,
    lock: AcmeLockBackend,
    http01: Arc<Http01ChallengeStore>,
    dns01: Option<Arc<dyn Dns01Provider>>,
) {
    loop {
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
    }
}

/// 在互斥锁内二次检查到期状态并执行一个 ACME order。
///
/// # 参数
/// - `tls`: 证书输出与校验配置。
/// - `acme`: ACME order 配置。
/// - `lock`: 已初始化的互斥后端。
/// - `http01`: challenge 发布表。
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

/// 构造包含域名集合的锁 key，避免同集群不同证书目标互相阻塞。
///
/// # 参数
/// - `acme`: 已规范化域名与用户配置的锁前缀。
///
/// 返回：稳定、可读的 Redis 业务锁 key；只在低频续期控制面分配。
#[cfg(feature = "redis-runtime")]
fn acme_lock_key(acme: &AcmeRuntimeCfg) -> String {
    format!("{}:{}", acme.lock_key, acme.domains.join(","))
}

/// 执行完整 HTTP-01 或 DNS-01 order，并把新 keypair 安装到 TLS watcher 的事实源路径。
///
/// # 参数
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

/// 从 SecretSource 文件恢复 ACME 账户；首次使用时创建并以 0600 原子持久化凭据。
///
/// # 参数
/// - `acme`: directory/contact/account 文件配置。
///
/// 返回：可创建 order 的账户。损坏凭据不会被覆盖，而是失败保留供人工恢复。
async fn load_or_create_account(acme: &AcmeRuntimeCfg) -> Result<Account> {
    let account_file = acme.account_credentials_file.clone();
    let existing = tokio::task::spawn_blocking(move || {
        crate::bounded_io::read_optional_file(
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

/// 构造与 gateway rustls provider 一致的 instant-acme 账户 builder。
///
/// # 参数
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

/// 判断现有 PEM 证书是否进入续期窗口；文件不存在视为需要签发。
///
/// # 参数
/// - `tls`: TLS 默认 pair 与可选 manifest 指针。
/// - `renew_before_days`: 到期前续期窗口。
///
/// 返回：缺失或 `notAfter <= now + window` 为 true；PEM/X.509 损坏返回错误，不盲目覆盖证据。
fn certificate_needs_renewal(tls: &TlsRuntimeCfg, renew_before_days: u64) -> Result<bool> {
    let (cert_file, _) = crate::tls::active_keypair_paths(tls)?;
    let bytes = match crate::bounded_io::read_optional_file(
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

/// 校验 ACME 返回的 PEM keypair后，以同目录临时文件 + rename 安装到 TLS 事实源。
///
/// # 参数
/// - `tls`: 最终 cert/key 路径及其它 TLS 配置。
/// - `certificate_pem`: ACME 返回的完整证书链。
/// - `private_key_pem`: 与 leaf 匹配的私钥。
fn install_keypair_atomically(
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
    } else {
        // 兼容未开启 manifest 的旧配置。watcher 遇到两个 rename 之间的混合 pair 会
        // 构建失败并保留旧 ServerConfig；对崩溃一致性有强需求时必须配 manifest。
        atomic_write(&tls.key_file, private_key_pem, true)?;
        atomic_write(&tls.cert_file, certificate_pem, false)?;
    }
    Ok(())
}

struct PreparedKeypairVersion {
    directory: PathBuf,
    manifest: Vec<u8>,
}

/// 把完整 pair 写入不可变版本目录，但不切换当前 manifest。
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

/// 在落盘前验证证书链可解析、私钥算法受 rustls 支持且 leaf/key 匹配。
///
/// # 参数
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

/// 把一个文件同目录原子替换，并在 secret 模式下强制 0600 权限。
///
/// # 参数
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
        options.mode(if secret { 0o600 } else { 0o644 });
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

/// Unix 上 fsync 目录项，使 create/rename 在突然断电后也有可预期持久性。
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

#[path = "../../tests/unit/acme.rs"]
#[cfg(test)]
mod tests;
