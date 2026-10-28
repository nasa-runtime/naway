//! SPIRE Workload API 的 X.509-SVID 订阅与动态身份快照。
//!
//! Workload API 通过 Unix socket 的调用方凭据完成 workload selector 授权；客户端请求不携带
//! selector。Naway 只从 Agent 已授权的完整响应中选择配置指定的 SPIFFE ID 与 hint，并把身份
//! 删除、federation bundle 删除和到期事实直接落实为停止新 TLS 握手。

use std::collections::HashMap;
#[cfg(feature = "spire-workload")]
use std::collections::HashSet;
#[cfg(feature = "spire-workload")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(feature = "spire-workload")]
use anyhow::Context;
use anyhow::Result;
use arc_swap::ArcSwapOption;
use tokio_rustls::rustls::client::ResolvesClientCert;
use tokio_rustls::rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
#[cfg(feature = "spire-workload")]
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
#[cfg(feature = "spire-workload")]
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
#[cfg(feature = "spire-workload")]
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::SignatureScheme;
#[cfg(feature = "spire-workload")]
use x509_cert::der::Decode;

use crate::config::model::SpireWorkloadCfg;

#[cfg(feature = "spire-workload")]
const MAX_SVIDS: usize = 64;
#[cfg(feature = "spire-workload")]
const MAX_CERTIFICATES_PER_CHAIN: usize = 16;
#[cfg(feature = "spire-workload")]
const MAX_FEDERATION_BUNDLES: usize = 128;
#[cfg(feature = "spire-workload")]
const MAX_CRLS: usize = 128;
#[cfg(feature = "spire-workload")]
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
#[cfg(feature = "spire-workload")]
const MAX_HINT_BYTES: usize = 1024;

#[derive(Clone, PartialEq, Eq)]
struct SpireSourceConfig {
    socket_path: PathBuf,
    spiffe_id: String,
    trust_domain: String,
    hint: Option<String>,
    federation_trust_domains: Arc<[String]>,
    timeout: Duration,
    reconnect_min: Duration,
    reconnect_max: Duration,
    max_response_bytes: usize,
    min_validity: Duration,
    clock_skew: Duration,
}

/// 一次完整且已验证的 Workload API 身份、信任束与吊销材料。
pub(crate) struct SpireMaterial {
    /// 当前 SVID 的 rustls 签名身份；私钥只驻留于该不可调试对象。
    pub(crate) identity: Arc<CertifiedKey>,
    /// 按规范化 trust domain 隔离的验证根，禁止跨域混用 CA。
    pub(crate) trust_bundles: HashMap<String, Arc<[CertificateDer<'static>]>>,
    /// Agent 随同完整响应提供的 CRL 集合。
    pub(crate) crls: Arc<[CertificateRevocationListDer<'static>]>,
    /// 叶证书的绝对到期时刻；resolver 在每次握手前复验。
    pub(crate) not_after: SystemTime,
}

/// 一个配置候选持有的 SPIRE 身份源。
///
/// 私钥和证书不实现配置序列化或诊断输出；`current` 的清空表示当前 workload 已失去使用该身份的
/// 权威，新握手必须立即失败，既有 TLS 连接不受影响。
pub struct SpireTlsSource {
    cfg: SpireSourceConfig,
    current: ArcSwapOption<SpireMaterial>,
    upstream_watcher_started: AtomicBool,
}

impl std::fmt::Debug for SpireTlsSource {
    /// 业务作用：提供不含证书、私钥、bundle 和 socket 细节的低敏诊断视图。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：只输出公开 SPIFFE ID 和是否持有未到期身份。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpireTlsSource")
            .field("spiffe_id", &self.cfg.spiffe_id)
            .field("active", &self.current().is_some())
            .finish()
    }
}

impl PartialEq for SpireTlsSource {
    /// 业务作用：按声明式 SPIRE 来源比较 listener 拓扑，不把轮换中的私钥材料纳入配置 diff。
    ///
    /// 参数说明：
    /// - `other`：是另一候选的 SPIRE 来源。
    ///
    /// 返回：socket、身份选择、资源门和重连策略全部相同时返回 true。
    fn eq(&self, other: &Self) -> bool {
        self.cfg == other.cfg
    }
}

impl Eq for SpireTlsSource {}

impl SpireTlsSource {
    /// 业务作用：生成不含证书与私钥的稳定来源标识，供上游连接池隔离不同 SPIRE 身份配置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回由 socket、SPIFFE ID、hint、federation allowlist 与安全门组成的内部标识。
    pub(crate) fn identity_key(&self) -> String {
        format!(
            "{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}|{:?}",
            self.cfg.socket_path.display(),
            self.cfg.spiffe_id,
            self.cfg.hint,
            self.cfg.federation_trust_domains,
            self.cfg.timeout,
            self.cfg.reconnect_min,
            self.cfg.reconnect_max,
            self.cfg.max_response_bytes,
            self.cfg.min_validity,
            self.cfg.clock_skew
        )
    }

    /// 业务作用：读取当前仍在证书有效期内的身份快照，供每次 TLS 握手执行失权门禁。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：存在未到期完整响应时返回快照；身份被删除、尚未取得或已到期时返回空。
    pub(crate) fn current(&self) -> Option<Arc<SpireMaterial>> {
        self.current
            .load_full()
            .filter(|material| SystemTime::now() < material.not_after)
    }

    /// 业务作用：启动上游客户端身份的单一后台订阅，使常驻连接池在新握手时读取最新 SVID。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：首次调用且当前存在 Tokio runtime 时启动；重复调用保持幂等。
    pub(crate) fn ensure_upstream_watcher(self: &Arc<Self>) {
        if self
            .upstream_watcher_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let source = self.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    watch_loop(source, None, || {}).await;
                });
            }
            Err(error) => {
                self.upstream_watcher_started
                    .store(false, Ordering::Release);
                tracing::warn!(error = %error, "SPIRE upstream identity subscription requires a Tokio runtime");
            }
        }
    }
}

/// 业务作用：构建并首次认证一个 SPIRE Workload API 身份源，候选发布前必须取得完整有效 SVID。
///
/// 参数说明：
/// - `cfg`：声明 Unix socket、精确身份、federation allowlist 与资源上限。
///
/// 返回：首个完整响应通过身份、证书链、私钥、bundle 和有效期复验时返回来源；否则拒绝候选。
pub fn build_source(cfg: &SpireWorkloadCfg) -> Result<Arc<SpireTlsSource>> {
    #[cfg(not(feature = "spire-workload"))]
    {
        let _ = cfg;
        anyhow::bail!("SPIRE Workload API requires the `spire-workload` feature");
    }
    #[cfg(feature = "spire-workload")]
    {
        let cfg = validate_config(cfg)?;
        let wait = cfg.timeout.saturating_add(Duration::from_secs(1));
        let thread_cfg = cfg.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("naway-spire-bootstrap".to_owned())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build SPIRE bootstrap runtime")
                    .and_then(|runtime| runtime.block_on(fetch_initial_material(&thread_cfg)));
                let _ = tx.send(result);
            })
            .context("spawn SPIRE bootstrap worker")?;
        let material = rx
            .recv_timeout(wait)
            .map_err(|_| anyhow::anyhow!("SPIRE Workload API bootstrap exceeded deadline"))??;
        Ok(Arc::new(SpireTlsSource {
            cfg,
            current: ArcSwapOption::from(Some(material)),
            upstream_watcher_started: AtomicBool::new(false),
        }))
    }
}

/// 业务作用：启动与 listener generation 同寿命的 Workload API 流式订阅。
///
/// 参数说明：
/// - `source`：是已取得首个身份的来源
/// - `shutdown`：撤销当前 listener 权威
/// - `on_change`：在完整新快照发布或身份被删除后触发，用于重建动态客户端信任验证器。
///
/// 返回：无同步返回值；断流会在证书有效期内退避重连，明确身份删除会立即清空来源。
pub fn spawn_listener_watcher<F>(
    source: Arc<SpireTlsSource>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    on_change: F,
) where
    F: FnMut() + Send + 'static,
{
    tokio::spawn(watch_loop(source, shutdown, on_change));
}

/// SPIRE 服务端身份 resolver；每次握手读取来源并复验证书到期事实。
pub(crate) struct SpireServerCertResolver {
    source: Arc<SpireTlsSource>,
}

impl SpireServerCertResolver {
    /// 业务作用：把动态 SPIRE 来源绑定到服务端握手选证接口。
    ///
    /// 参数说明：
    /// - `source`：是当前 listener 的独占身份来源。
    ///
    /// 返回：返回只读取该来源的 resolver，不复制或导出私钥。
    pub(crate) fn new(source: Arc<SpireTlsSource>) -> Self {
        Self {
            source,
        }
    }
}

impl std::fmt::Debug for SpireServerCertResolver {
    /// 业务作用：输出不含身份材料的服务端 resolver 状态。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：只输出当前是否可完成新握手。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpireServerCertResolver")
            .field("active", &self.source.current().is_some())
            .finish()
    }
}

impl ResolvesServerCert for SpireServerCertResolver {
    /// 业务作用：在握手选证点执行 SPIRE 身份失权和到期门禁。
    ///
    /// 参数说明：
    /// - `_client_hello`：不参与身份选择；一个 listener 只绑定一个已授权 SVID。
    ///
    /// 返回：身份仍有效时返回当前证书与签名键；否则返回空并拒绝新握手。
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.source
            .current()
            .map(|material| material.identity.clone())
    }
}

/// SPIRE 上游客户端身份 resolver；连接池无需因短期 SVID 轮换重建。
pub(crate) struct SpireClientCertResolver {
    source: Arc<SpireTlsSource>,
}

impl SpireClientCertResolver {
    /// 业务作用：把动态 SPIRE 来源绑定到上游 mTLS 客户端选证接口。
    ///
    /// 参数说明：
    /// - `source`：是服务配置已授权的身份来源。
    ///
    /// 返回：返回在每次新握手时读取当前 SVID 的 resolver。
    pub(crate) fn new(source: Arc<SpireTlsSource>) -> Self {
        Self {
            source,
        }
    }
}

impl std::fmt::Debug for SpireClientCertResolver {
    /// 业务作用：输出不含身份材料的客户端 resolver 状态。
    ///
    /// 参数说明：
    /// - `formatter`：是标准格式化目标。
    ///
    /// 返回：只输出当前是否持有可用 SVID。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpireClientCertResolver")
            .field("active", &self.source.current().is_some())
            .finish()
    }
}

impl ResolvesClientCert for SpireClientCertResolver {
    /// 业务作用：为新上游 mTLS 握手选择当前未到期且算法相容的 SVID。
    ///
    /// 参数说明：
    /// - `_root_hint_subjects`：仅是对端提示，不能放宽配置身份
    /// - `sigschemes`：是对端算法集。
    ///
    /// 返回：身份有效且签名算法有交集时返回；失权、到期或算法不相容时不发送客户端证书。
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.source.ensure_upstream_watcher();
        let material = self.source.current()?;
        material.identity.key.choose_scheme(sigschemes)?;
        Some(material.identity.clone())
    }

    /// 业务作用：向 rustls 声明当前是否可能提供客户端证书，保持证书请求协商与失权状态一致。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前 SVID 未到期时为 true，否则为 false。
    fn has_certs(&self) -> bool {
        self.source.current().is_some()
    }
}

/// 业务作用：解析并约束 SPIRE 配置，避免不明确 socket、身份或资源边界进入控制面。
///
/// 参数说明：
/// - `cfg`：是 YAML 反序列化结果。
///
/// 返回：所有字段规范化且上限自洽时返回内部配置；否则拒绝候选。
#[cfg(feature = "spire-workload")]
fn validate_config(cfg: &SpireWorkloadCfg) -> Result<SpireSourceConfig> {
    let socket_path = Path::new(cfg.socket_path.trim());
    anyhow::ensure!(
        socket_path.is_absolute(),
        "SPIRE socket_path must be absolute"
    );
    anyhow::ensure!(
        cfg.timeout_ms >= 100 && cfg.timeout_ms <= 30_000,
        "SPIRE timeout_ms must be within 100..=30000"
    );
    anyhow::ensure!(
        cfg.reconnect_min_ms >= 10,
        "SPIRE reconnect_min_ms must be at least 10"
    );
    anyhow::ensure!(
        cfg.reconnect_max_ms >= cfg.reconnect_min_ms && cfg.reconnect_max_ms <= 60_000,
        "SPIRE reconnect_max_ms must be within reconnect_min_ms..=60000"
    );
    anyhow::ensure!(
        cfg.max_response_bytes >= 64 * 1024 && cfg.max_response_bytes <= 16 * 1024 * 1024,
        "SPIRE max_response_bytes must be within 65536..=16777216"
    );
    anyhow::ensure!(
        cfg.min_validity_seconds >= 1 && cfg.min_validity_seconds <= 3600,
        "SPIRE min_validity_seconds must be within 1..=3600"
    );
    anyhow::ensure!(
        cfg.clock_skew_seconds <= 300,
        "SPIRE clock_skew_seconds must not exceed 300"
    );
    let (spiffe_id, trust_domain) = crate::config::normalize_spiffe_id(&cfg.spiffe_id)?;
    let hint = cfg
        .hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if let Some(hint) = &hint {
        anyhow::ensure!(
            hint.len() <= MAX_HINT_BYTES,
            "SPIRE hint exceeds 1024 bytes"
        );
    }
    let mut federation = cfg
        .federation_trust_domains
        .iter()
        .map(|domain| crate::config::normalize_spiffe_trust_domain(domain))
        .collect::<Result<Vec<_>>>()?;
    federation.sort();
    federation.dedup();
    anyhow::ensure!(
        federation.len() <= MAX_FEDERATION_BUNDLES,
        "SPIRE federation trust-domain allowlist exceeds 128 entries"
    );
    anyhow::ensure!(
        !federation.iter().any(|domain| domain == &trust_domain),
        "SPIRE local trust domain must not be repeated as a federation domain"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        let metadata = std::fs::metadata(socket_path)
            .with_context(|| format!("read SPIRE socket metadata {}", socket_path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_socket(),
            "SPIRE socket_path is not a Unix socket"
        );
    }
    Ok(SpireSourceConfig {
        socket_path: socket_path.to_path_buf(),
        spiffe_id,
        trust_domain,
        hint,
        federation_trust_domains: Arc::from(federation),
        timeout: Duration::from_millis(cfg.timeout_ms),
        reconnect_min: Duration::from_millis(cfg.reconnect_min_ms),
        reconnect_max: Duration::from_millis(cfg.reconnect_max_ms),
        max_response_bytes: cfg.max_response_bytes,
        min_validity: Duration::from_secs(cfg.min_validity_seconds),
        clock_skew: Duration::from_secs(cfg.clock_skew_seconds),
    })
}

#[cfg(feature = "spire-workload")]
#[derive(Clone, PartialEq, prost::Message)]
struct X509SvidRequest {}

#[cfg(feature = "spire-workload")]
#[derive(Clone, PartialEq, prost::Message)]
struct X509SvidResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<X509Svid>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    crl: Vec<Vec<u8>>,
    #[prost(map = "string, bytes", tag = "3")]
    federated_bundles: HashMap<String, Vec<u8>>,
}

#[cfg(feature = "spire-workload")]
#[derive(Clone, PartialEq, prost::Message)]
struct X509Svid {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(bytes = "vec", tag = "2")]
    x509_svid: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    x509_svid_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    bundle: Vec<u8>,
    #[prost(string, tag = "5")]
    hint: String,
}

#[cfg(feature = "spire-workload")]
enum ResponseValidation {
    Active(Arc<SpireMaterial>),
    Redacted,
}

#[cfg(feature = "spire-workload")]
/// 业务作用：取得启动期首个完整 Workload API 响应并在返回前验证全部身份材料。
///
/// 参数说明：
/// - `cfg`：是已规范化的来源与安全上限。
///
/// 返回：首响应包含指定身份和全部声明 federation bundle 时返回材料；失权、超时或坏材料失败。
async fn fetch_initial_material(cfg: &SpireSourceConfig) -> Result<Arc<SpireMaterial>> {
    let mut stream = open_svid_stream(cfg).await?;
    let response = tokio::time::timeout(cfg.timeout, stream.message())
        .await
        .context("wait for initial SPIRE X509-SVID response")??
        .context("SPIRE X509-SVID stream ended before initial response")?;
    match validate_response(cfg, response)? {
        ResponseValidation::Active(material) => Ok(material),
        ResponseValidation::Redacted => {
            anyhow::bail!("SPIRE did not authorize the configured identity or federation bundles")
        }
    }
}

#[cfg(feature = "spire-workload")]
/// 业务作用：持续消费完整 SVID 响应，并把失权、轮换、断流与证书到期映射为确定状态。
///
/// 参数说明：
/// - `source`：持有当前快照
/// - `shutdown`：可撤销 listener generation
/// - `on_change`：重建消费者。
///
/// 返回：任务只在 generation 停止时结束；依赖断流按有界退避重连。
async fn watch_loop<F>(
    source: Arc<SpireTlsSource>,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    mut on_change: F,
) where
    F: FnMut() + Send + 'static,
{
    let mut backoff = source.cfg.reconnect_min;
    loop {
        if shutdown.as_ref().is_some_and(|receiver| *receiver.borrow()) {
            return;
        }
        let mut received_response = false;
        let session = consume_stream(
            &source,
            &mut on_change,
            shutdown.as_mut(),
            &mut received_response,
        )
        .await;
        if received_response {
            // 已收到 Agent 的完整响应说明依赖恢复健康，后续断流应从最小退避重新开始。
            backoff = source.cfg.reconnect_min;
        }
        match session {
            Ok(()) => return,
            Err(error) => {
                let permission_denied = error
                    .downcast_ref::<tonic::Status>()
                    .is_some_and(|status| status.code() == tonic::Code::PermissionDenied);
                if permission_denied {
                    // RPC 建立阶段同样可能直接返回 PermissionDenied，语义与流内撤权一致。
                    source.current.store(None);
                    on_change();
                    tracing::warn!(error = %format!("{error:#}"), "SPIRE Workload API selector authorization was revoked");
                } else {
                    tracing::warn!(error = %format!("{error:#}"), "SPIRE Workload API stream interrupted; retaining identity only until its certificate expires");
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = wait_for_shutdown(shutdown.as_mut()) => return,
        }
        backoff = backoff.saturating_mul(2).min(source.cfg.reconnect_max);
    }
}

#[cfg(not(feature = "spire-workload"))]
/// 业务作用：为未编译 SPIRE transport 的制品保留统一调用边界。
///
/// 参数说明：
/// - `_source`：未启用 feature 时保留的身份来源参数。
/// - `_shutdown`：未启用 feature 时保留的入口换代停止信号。
/// - `_on_change`：未启用 feature 时保留的材料变化回调，不触发身份发布。
///
/// 返回：该分支不会被成功构造的来源调用。
async fn watch_loop<F>(
    _source: Arc<SpireTlsSource>,
    _shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    _on_change: F,
) where
    F: FnMut() + Send + 'static,
{
}

#[cfg(feature = "spire-workload")]
/// 业务作用：消费一次 gRPC stream，会话内每条消息都按完整替换语义处理。
///
/// 参数说明：
/// - `source`：接收更新
/// - `on_change`：通知消费者
/// - `shutdown`：可停止当前阻塞读取
/// - `received_response`：记录本次会话是否已经收到完整响应，供外层复位重连退避。
///
/// 返回：主动停止返回成功；断流或 RPC 错误返回失败并由外层重连。
async fn consume_stream<F>(
    source: &Arc<SpireTlsSource>,
    on_change: &mut F,
    shutdown: Option<&mut tokio::sync::watch::Receiver<bool>>,
    received_response: &mut bool,
) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    let mut stream = open_svid_stream(&source.cfg).await?;
    let first = tokio::time::timeout(source.cfg.timeout, stream.message())
        .await
        .context("wait for SPIRE stream first response")?;
    let first = match first {
        Ok(message) => message,
        Err(status) => return Err(status).context("read SPIRE stream first response"),
    };
    let mut next = first.context("SPIRE stream ended before first response")?;
    let mut shutdown = shutdown;
    loop {
        apply_response(source, next, on_change);
        *received_response = true;
        let message = tokio::select! {
            message = stream.message() => message,
            _ = wait_for_shutdown(shutdown.as_deref_mut()) => return Ok(()),
        };
        next = match message {
            Ok(Some(message)) => message,
            Ok(None) => anyhow::bail!("SPIRE X509-SVID stream ended"),
            Err(status) => return Err(status).context("read SPIRE X509-SVID stream"),
        };
    }
}

#[cfg(feature = "spire-workload")]
/// 业务作用：把一条完整响应原子转换成新身份或明确失权状态。
///
/// 参数说明：
/// - `source`：是发布目标
/// - `response`：是 Agent 当前完整授权集合
/// - `on_change`：通知消费者。
///
/// 返回：无返回值；坏材料保留未到期旧值，身份或 bundle 被删除则立即清空。
fn apply_response<F>(source: &Arc<SpireTlsSource>, response: X509SvidResponse, on_change: &mut F)
where
    F: FnMut() + Send + 'static,
{
    match validate_response(&source.cfg, response) {
        Ok(ResponseValidation::Active(material)) => {
            source.current.store(Some(material));
            on_change();
        }
        Ok(ResponseValidation::Redacted) => {
            // 完整响应中缺少已用身份或声明 bundle 是撤权事实，必须先关闭新握手再通知消费者。
            source.current.store(None);
            on_change();
            tracing::warn!(spiffe_id = %source.cfg.spiffe_id, "SPIRE identity or required federation bundle was removed");
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "discarding invalid SPIRE Workload API response")
        }
    }
}

#[cfg(feature = "spire-workload")]
/// 业务作用：等待可选 generation 停止信号，None 时保持永不就绪。
///
/// 参数说明：
/// - `shutdown`：是可选监听代广播。
///
/// 返回：广播关闭或值变为 true 时结束。
async fn wait_for_shutdown(shutdown: Option<&mut tokio::sync::watch::Receiver<bool>>) {
    match shutdown {
        Some(receiver) => {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(feature = "spire-workload")]
/// 业务作用：通过本地 Unix socket 建立带标准安全 header 的 FetchX509SVID server stream。
///
/// 参数说明：
/// - `cfg`：固定 socket、deadline 与最大解码字节。
///
/// 返回：RPC 就绪后返回响应流；socket、HTTP/2、gRPC 状态或 header 构造失败均返回错误。
async fn open_svid_stream(cfg: &SpireSourceConfig) -> Result<tonic::Streaming<X509SvidResponse>> {
    use tonic::client::Grpc;
    use tonic::transport::Endpoint;

    let socket = cfg.socket_path.clone();
    let connector = tower::service_fn(move |_| {
        let socket = socket.clone();
        async move {
            tokio::net::UnixStream::connect(socket)
                .await
                .map(hyper_util::rt::TokioIo::new)
        }
    });
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_timeout(cfg.timeout)
        .connect_with_connector(connector)
        .await
        .context("connect SPIRE Workload API socket")?;
    let mut grpc = Grpc::new(channel)
        .max_decoding_message_size(cfg.max_response_bytes)
        .max_encoding_message_size(1024);
    grpc.ready().await.context("SPIRE gRPC service not ready")?;
    let mut request = tonic::Request::new(X509SvidRequest {});
    request.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::MetadataValue::from_static("true"),
    );
    let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchX509SVID");
    let codec = tonic_prost::ProstCodec::<X509SvidRequest, X509SvidResponse>::default();
    Ok(grpc
        .server_streaming(request, path, codec)
        .await
        .context("open SPIRE FetchX509SVID stream")?
        .into_inner())
}

#[cfg(feature = "spire-workload")]
/// 业务作用：验证一条完整 Workload API 响应并构造不可变 TLS 身份快照。
///
/// 参数说明：
/// - `cfg`：固定精确身份与 federation allowlist
/// - `response`：是当前完整授权集合。
///
/// 返回：材料完整有效时返回 Active；身份或必需 bundle 缺失返回 Redacted；其它坏材料返回错误。
fn validate_response(
    cfg: &SpireSourceConfig,
    response: X509SvidResponse,
) -> Result<ResponseValidation> {
    if response.svids.is_empty() {
        return Ok(ResponseValidation::Redacted);
    }
    anyhow::ensure!(
        response.svids.len() <= MAX_SVIDS,
        "SPIRE response contains too many SVIDs"
    );
    anyhow::ensure!(
        response.federated_bundles.len() <= MAX_FEDERATION_BUNDLES,
        "SPIRE response contains too many federation bundles"
    );
    anyhow::ensure!(
        response.crl.len() <= MAX_CRLS,
        "SPIRE response contains too many CRLs"
    );
    let total = response
        .svids
        .iter()
        .fold(0usize, |sum, svid| {
            sum.saturating_add(svid.spiffe_id.len())
                .saturating_add(svid.hint.len())
                .saturating_add(svid.x509_svid.len())
                .saturating_add(svid.x509_svid_key.len())
                .saturating_add(svid.bundle.len())
        })
        .saturating_add(response.crl.iter().map(Vec::len).sum::<usize>())
        .saturating_add(
            response
                .federated_bundles
                .iter()
                .map(|(domain, bundle)| domain.len().saturating_add(bundle.len()))
                .sum::<usize>(),
        );
    anyhow::ensure!(
        total <= cfg.max_response_bytes,
        "SPIRE response exceeds configured byte limit"
    );

    let selected = response
        .svids
        .iter()
        .filter(|svid| {
            svid.spiffe_id == cfg.spiffe_id
                && cfg.hint.as_deref().is_none_or(|hint| svid.hint == hint)
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(ResponseValidation::Redacted);
    }
    anyhow::ensure!(
        selected.len() == 1,
        "SPIRE response contains an ambiguous configured identity; set a unique hint"
    );
    let selected = selected[0];
    anyhow::ensure!(
        !selected.x509_svid.is_empty()
            && !selected.x509_svid_key.is_empty()
            && !selected.bundle.is_empty(),
        "SPIRE selected SVID has an empty mandatory field"
    );
    anyhow::ensure!(
        selected.x509_svid_key.len() <= MAX_PRIVATE_KEY_BYTES,
        "SPIRE SVID private key exceeds byte limit"
    );

    let chain = split_certificate_bundle(&selected.x509_svid, "SPIRE SVID chain")?;
    let local_bundle = split_certificate_bundle(&selected.bundle, "SPIRE local trust bundle")?;
    let mut trust_bundles = HashMap::new();
    trust_bundles.insert(cfg.trust_domain.clone(), Arc::from(local_bundle.clone()));
    let mut seen_domains = HashSet::new();
    for (raw_domain, bytes) in response.federated_bundles {
        let domain = normalize_bundle_trust_domain(&raw_domain)?;
        anyhow::ensure!(
            seen_domains.insert(domain.clone()),
            "SPIRE response contains duplicate normalized federation domain"
        );
        if cfg.federation_trust_domains.binary_search(&domain).is_ok() {
            trust_bundles.insert(
                domain,
                Arc::from(split_certificate_bundle(&bytes, "SPIRE federation bundle")?),
            );
        }
    }
    if cfg
        .federation_trust_domains
        .iter()
        .any(|domain| !trust_bundles.contains_key(domain))
    {
        return Ok(ResponseValidation::Redacted);
    }

    validate_leaf_identity(cfg, &chain[0])?;
    validate_chain(&chain, &local_bundle)?;
    let key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(selected.x509_svid_key.clone()).into();
    let signing_key = tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .context("parse SPIRE SVID PKCS#8 private key")?;
    let certified = CertifiedKey::new(chain.clone(), signing_key);
    certified
        .keys_match()
        .context("SPIRE SVID certificate and private key do not match")?;

    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref())
        .map_err(|error| anyhow::anyhow!("parse SPIRE SVID leaf validity: {error}"))?;
    let not_after_secs = u64::try_from(leaf.validity().not_after.timestamp())
        .context("SPIRE SVID notAfter precedes Unix epoch")?;
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(not_after_secs);
    anyhow::ensure!(
        not_after
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            >= cfg.min_validity,
        "SPIRE SVID does not satisfy minimum remaining validity"
    );

    let mut crls = Vec::with_capacity(response.crl.len());
    for bytes in response.crl {
        anyhow::ensure!(!bytes.is_empty(), "SPIRE response contains an empty CRL");
        x509_cert::crl::CertificateList::from_der(&bytes).context("parse SPIRE CRL")?;
        crls.push(CertificateRevocationListDer::from(bytes));
    }
    Ok(ResponseValidation::Active(Arc::new(SpireMaterial {
        identity: Arc::new(certified),
        trust_bundles,
        crls: Arc::from(crls),
        not_after,
    })))
}

#[cfg(feature = "spire-workload")]
/// 业务作用：把 Workload API map key 的 trust-domain SPIFFE ID 收敛成内部裸域名键。
///
/// 参数说明：
/// - `raw`：必须是无 path 的 `spiffe://<trust-domain>`，不得携带 workload、port 或 query。
///
/// 返回：合法 trust-domain ID 返回小写域名；其它 URI 形态拒绝整个响应。
fn normalize_bundle_trust_domain(raw: &str) -> Result<String> {
    let (identity, domain) = crate::config::normalize_spiffe_id(raw)?;
    anyhow::ensure!(
        identity == format!("spiffe://{domain}"),
        "SPIRE federation bundle key must identify a trust domain without a workload path"
    );
    Ok(domain)
}

#[cfg(feature = "spire-workload")]
/// 业务作用：拆分 Workload API 的连续 DER 证书序列，并限制证书数量和空尾部。
///
/// 参数说明：
/// - `bytes`：是一条 chain 或 bundle
/// - `label`：仅用于低敏错误定位。
///
/// 返回：每张证书完整解析且数量在上限内时返回 owned DER 集合，否则拒绝响应。
fn split_certificate_bundle(bytes: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>> {
    anyhow::ensure!(!bytes.is_empty(), "{label} is empty");
    let mut remaining = bytes;
    let mut certs = Vec::new();
    while !remaining.is_empty() {
        anyhow::ensure!(
            certs.len() < MAX_CERTIFICATES_PER_CHAIN,
            "{label} contains too many certificates"
        );
        let before = remaining.len();
        let (next, _) = x509_parser::parse_x509_certificate(remaining)
            .map_err(|error| anyhow::anyhow!("parse {label}: {error}"))?;
        let consumed = before.saturating_sub(next.len());
        anyhow::ensure!(consumed > 0, "{label} parser made no progress");
        certs.push(CertificateDer::from(remaining[..consumed].to_vec()));
        remaining = next;
    }
    Ok(certs)
}

#[cfg(feature = "spire-workload")]
/// 业务作用：验证 SVID 叶证书只声明配置选定的唯一 SPIFFE URI SAN 且处于可接受时间窗口。
///
/// 参数说明：
/// - `cfg`：固定身份与时钟偏差
/// - `leaf`：是证书链首项。
///
/// 返回：身份、SAN 类型和有效期全部满足 X.509-SVID 门禁时成功，否则拒绝响应。
fn validate_leaf_identity(cfg: &SpireSourceConfig, leaf: &CertificateDer<'_>) -> Result<()> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parse SPIRE SVID leaf: {error}"))?;
    let san = certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => Some(names),
            _ => None,
        })
        .context("SPIRE SVID leaf has no subjectAltName")?;
    anyhow::ensure!(
        san.general_names.len() == 1,
        "SPIRE SVID leaf must contain exactly one SAN"
    );
    let GeneralName::URI(uri) = san.general_names[0] else {
        anyhow::bail!("SPIRE SVID leaf SAN must be a URI");
    };
    let (identity, domain) = crate::config::normalize_spiffe_id(uri)?;
    anyhow::ensure!(
        identity == cfg.spiffe_id && domain == cfg.trust_domain,
        "SPIRE SVID leaf identity does not match configured SPIFFE ID"
    );
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let now = i64::try_from(now)?;
    let skew = i64::try_from(cfg.clock_skew.as_secs())?;
    anyhow::ensure!(
        certificate.validity().not_before.timestamp() <= now.saturating_add(skew),
        "SPIRE SVID is not yet valid"
    );
    anyhow::ensure!(
        certificate.validity().not_after.timestamp() > now,
        "SPIRE SVID is expired"
    );
    Ok(())
}

#[cfg(feature = "spire-workload")]
/// 业务作用：验证选定 SVID 链由其同响应 local bundle 授权，防止只校验 key match 的伪身份发布。
///
/// 参数说明：
/// - `chain`：首项是 SVID
/// - `bundle`：只属于该 SVID 的 trust domain。
///
/// 返回：标准客户端身份链验证成功时返回；未知根、用途、时间或链签名错误均拒绝响应。
fn validate_chain(
    chain: &[CertificateDer<'static>],
    bundle: &[CertificateDer<'static>],
) -> Result<()> {
    let mut roots = RootCertStore::empty();
    for root in bundle {
        roots
            .add(root.clone())
            .context("add SPIRE local trust anchor")?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .context("build SPIRE SVID chain verifier")?;
    verifier
        .verify_client_cert(&chain[0], &chain[1..], UnixTime::now())
        .context("verify SPIRE SVID chain")?;
    Ok(())
}
