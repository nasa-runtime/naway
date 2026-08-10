//! V5 管理操作持久、防篡改审计。
//!
//! 管理写请求是低频控制面流量，可以为了安全等待落盘与外部 sink 确认；这条路径与数据面完全
//! 隔离。每条记录使用 HMAC-SHA256 串起前一条 MAC，启动时从头验证 sequence/chain/MAC，发现
//! 离线修改或重排立即 fail-fast。`Bytes` 同时用于 append 与 HTTP body，外发只增加引用计数。

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::config::model::{AdminAction, AdminResource};
use crate::config::AdminAuditRuntimeCfg;

/// 可查询的单条审计业务载荷；不保存 Authorization/Cookie/query 原文。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminAuditPayload {
    /// Unix epoch 毫秒。
    pub ts_ms: u128,
    /// RBAC principal id。
    pub principal: String,
    /// HTTP method。
    pub method: String,
    /// 不含 query 的管理 API path。
    pub path: String,
    /// 固定资源域名称。
    pub resource: String,
    /// 固定风险动作名称。
    pub action: String,
    /// `attempt` 或 `completed`。
    pub phase: String,
    /// completed 响应状态；attempt 为 None。
    pub status: Option<u16>,
    /// query 的 SHA-256 摘要；可关联相同操作但不泄漏 token/path 参数原文。
    pub query_sha256: Option<String>,
    /// 请求处理时的配置版本。
    pub config_version: u64,
}

/// 持久 JSONL 中的一条完整 hash-chain 记录。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredAdminAuditEvent {
    /// 从 1 开始连续递增，启动校验防删除中间记录/重排。
    pub sequence: u64,
    /// 前一条记录 HMAC；首条为空串。
    pub previous_hmac: String,
    /// 审计业务载荷。
    pub payload: AdminAuditPayload,
    /// 对 `sequence + previous_hmac + payload` canonical JSON 的 HMAC-SHA256。
    pub hmac_sha256: String,
}

/// HMAC 输入结构；字段顺序由 struct 固定，不依赖 map 排序。
#[derive(Serialize)]
struct UnsignedAdminAuditEvent<'a> {
    sequence: u64,
    previous_hmac: &'a str,
    payload: &'a AdminAuditPayload,
}

/// handler 提交的审计参数；借用 request 字段，直到构造拥有型 payload 才复制一次小字符串。
pub struct AdminAuditInput<'a> {
    /// 已认证主体。
    pub principal: Arc<str>,
    /// HTTP method。
    pub method: &'a str,
    /// 不含 query 的 path。
    pub path: &'a str,
    /// 固定资源域。
    pub resource: AdminResource,
    /// 固定风险动作。
    pub action: AdminAction,
    /// attempt/completed。
    pub phase: &'static str,
    /// completed 响应状态。
    pub status: Option<u16>,
    /// 可选 query 摘要。
    pub query_sha256: Option<String>,
    /// 当前配置版本。
    pub config_version: u64,
}

/// 进程级管理审计器；内部 mutex 串行低频写动作，维护严格 hash-chain 顺序。
#[derive(Clone)]
pub struct AdminAuditLog {
    active: Arc<ArcSwapOption<AdminAuditInner>>,
    write_gate: Arc<Mutex<()>>,
    transitioning: Arc<AtomicBool>,
}

struct AdminAuditInner {
    config: AdminAuditRuntimeCfg,
    client: Option<reqwest::Client>,
    chain: Mutex<AuditChain>,
}

struct AuditChain {
    next_sequence: u64,
    previous_hmac: String,
    recent: VecDeque<StoredAdminAuditEvent>,
}

impl AdminAuditLog {
    /// 打开并完整验证已有 spool；任一坏行/MAC 失配会阻止管理面启动。
    ///
    /// # 参数
    /// - `config`: 快照构建期已解析 SecretSource/endpoint/资源上限的审计计划。
    pub fn open(config: &AdminAuditRuntimeCfg) -> Result<Self> {
        let active = build_audit_generation(config)?;
        Ok(Self {
            active: Arc::new(ArcSwapOption::from(active)),
            write_gate: Arc::new(Mutex::new(())),
            transitioning: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 业务作用：在快照发布前准备新的审计 spool、hash-chain 和远端客户端。
    ///
    /// 参数说明：`config` 是候选快照已解密且完成边界校验的审计计划。
    ///
    /// 返回：本地链完整验证且 HTTP client 构建成功时返回候选代；失败不改变在线代。
    pub fn prepare_replacement(&self, config: &AdminAuditRuntimeCfg) -> Result<Self> {
        let active = build_audit_generation(config)?;
        Ok(Self {
            active: Arc::new(ArcSwapOption::from(active)),
            write_gate: self.write_gate.clone(),
            transitioning: self.transitioning.clone(),
        })
    }

    /// 业务作用：在快照切换前关闭审计写入准入，防止跨代序列或密钥混写。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；后续写操作失败闭合，直到候选代提交或取消。
    pub fn begin_transition(&self) {
        self.transitioning.store(true, Ordering::Release);
    }

    /// 业务作用：取消尚未发布的审计换代门禁，恢复旧代写入。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值。
    pub fn cancel_transition(&self) {
        self.transitioning.store(false, Ordering::Release);
    }

    /// 业务作用：在已发布快照后切换审计 owner，并等待已进入旧代的唯一写入结束。
    ///
    /// 参数说明：`candidate` 是通过 [`Self::prepare_replacement`] 构建的候选代。
    ///
    /// 返回：无返回值；方法返回时新写入只能看到候选 owner。
    pub async fn replace(&self, candidate: &Self) {
        let _gate = self.write_gate.lock().await;
        self.active.store(candidate.active.load_full());
        self.transitioning.store(false, Ordering::Release);
    }
}

/// 业务作用：打开并完整验证单个审计代，关闭态则构建空 owner。
///
/// 参数说明：`config` 是已解析的 spool、签名与远端 sink 计划。
///
/// 返回：启用时返回已验证代，关闭时返回 None；任一完整性或客户端错误失败。
fn build_audit_generation(config: &AdminAuditRuntimeCfg) -> Result<Option<Arc<AdminAuditInner>>> {
    if !config.enabled {
        return Ok(None);
    }
    if let Some(parent) = config.file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create admin audit dir {}", parent.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&config.file)
        .with_context(|| format!("open admin audit spool {}", config.file.display()))?;
    let chain = verify_spool(
        BufReader::new(file),
        config.signing_key.as_ref(),
        config.max_record_bytes,
        config.history_limit,
    )?;
    let client = config
        .endpoint
        .as_ref()
        .map(|_| {
            reqwest::Client::builder()
                .timeout(config.timeout)
                .user_agent("naway-admin-audit/1")
                .build()
                .context("build admin audit HTTP client")
        })
        .transpose()?;
    Ok(Some(Arc::new(AdminAuditInner {
        config: config.clone(),
        client,
        chain: Mutex::new(chain),
    })))
}

impl AdminAuditLog {
    /// 追加一条审计记录：本地 O_APPEND + 可选 fsync 成功后，再等待外部 sink 2xx。
    ///
    /// 写动作应在副作用前先写 `attempt`；任何错误均 fail-closed。`completed` 记录响应状态。
    ///
    /// # 参数
    /// - `input`: 已通过认证/RBAC 的小型审计字段，不含敏感 header/query 原文。
    pub async fn record(&self, input: AdminAuditInput<'_>) -> Result<()> {
        if self.transitioning.load(Ordering::Acquire) {
            bail!("admin audit generation is transitioning");
        }
        // 换代与记录共用写门，确保旧 owner 不会在新代验证完 sequence 后迟到追加。
        let _write_gate = self.write_gate.lock().await;
        if self.transitioning.load(Ordering::Acquire) {
            bail!("admin audit generation is transitioning");
        }
        let Some(inner) = self.active.load_full() else {
            return Ok(());
        };
        // 串行锁跨本地/远端确认是刻意设计：审计低频，严格 sequence 比吞吐更重要；数据面不经过此锁。
        let mut chain = inner.chain.lock().await;
        let payload = AdminAuditPayload {
            ts_ms: unix_now_ms(),
            principal: input.principal.to_string(),
            method: input.method.to_string(),
            path: input.path.to_string(),
            resource: resource_name(input.resource).to_string(),
            action: action_name(input.action).to_string(),
            phase: input.phase.to_string(),
            status: input.status,
            query_sha256: input.query_sha256,
            config_version: input.config_version,
        };
        let sequence = chain.next_sequence;
        let previous_hmac = chain.previous_hmac.clone();
        let unsigned = UnsignedAdminAuditEvent {
            sequence,
            previous_hmac: previous_hmac.as_str(),
            payload: &payload,
        };
        let canonical =
            serde_json::to_string(&unsigned).context("encode admin audit HMAC input")?;
        let hmac_sha256 =
            nasa::crypto::hmac_sha256(canonical.as_str(), inner.config.signing_key.as_ref());
        let stored = StoredAdminAuditEvent {
            sequence,
            previous_hmac,
            payload,
            hmac_sha256,
        };
        let encoded = serde_json::to_vec(&stored).context("encode admin audit event")?;
        if encoded.len() > inner.config.max_record_bytes {
            bail!("admin audit event exceeds configured max_record_bytes");
        }
        // `Bytes` owns serializer Vec without copying；HTTP body clone below只增加 refcount。
        let encoded = Bytes::from(encoded);
        append_local(&inner, encoded.as_ref()).await?;

        // 本地 append 成功后必须推进 chain，即使远端失败；否则下一次会与磁盘 sequence 分叉。
        chain.next_sequence = chain.next_sequence.saturating_add(1);
        chain.previous_hmac = stored.hmac_sha256.clone();
        chain.recent.push_back(stored);
        while chain.recent.len() > inner.config.history_limit {
            chain.recent.pop_front();
        }
        if let (Some(client), Some(endpoint)) = (&inner.client, &inner.config.endpoint) {
            send_remote(&inner, client, endpoint.as_ref(), encoded).await?;
        }
        Ok(())
    }

    /// 返回内存中的已验证尾部窗口；完整记录保留在 spool/外部 sink。
    pub async fn snapshot(&self) -> Vec<StoredAdminAuditEvent> {
        let Some(inner) = self.active.load_full() else {
            return Vec::new();
        };
        let events = inner.chain.lock().await.recent.iter().cloned().collect();
        events
    }
}

/// O_APPEND 写入一条 JSON 与换行；可选 sync_data 把控制面成功边界推进到持久介质。
async fn append_local(inner: &AdminAuditInner, encoded: &[u8]) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&inner.config.file)
        .await
        .with_context(|| format!("open admin audit spool {}", inner.config.file.display()))?;
    file.write_all(encoded)
        .await
        .context("append admin audit JSON")?;
    file.write_all(b"\n")
        .await
        .context("append admin audit newline")?;
    file.flush().await.context("flush admin audit spool")?;
    if inner.config.fsync {
        file.sync_data().await.context("sync admin audit spool")?;
    }
    Ok(())
}

/// 把与本地 append 共用的 `Bytes` 发往外部持久 sink，并有界排空响应以复用连接。
async fn send_remote(
    inner: &AdminAuditInner,
    client: &reqwest::Client,
    endpoint: &str,
    encoded: Bytes,
) -> Result<()> {
    let mut request = client
        .post(endpoint)
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(authorization) = &inner.config.authorization {
        request = request.header(http::header::AUTHORIZATION, authorization.clone());
    }
    let mut response = request
        .body(encoded)
        .send()
        .await
        .context("send admin audit event")?;
    if !response.status().is_success() {
        bail!("admin audit endpoint returned {}", response.status());
    }
    const MAX_RESPONSE_BYTES: usize = 16 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("admin audit response exceeds 16KiB");
    }
    let mut seen = 0_usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read admin audit response")?
    {
        seen = seen.saturating_add(chunk.len());
        if seen > MAX_RESPONSE_BYTES {
            bail!("admin audit response exceeds 16KiB");
        }
    }
    Ok(())
}

/// 启动时流式验证 JSONL；每次只保留单行 bounded buffer，spool 大小不会线性进入 RSS。
fn verify_spool(
    mut reader: impl BufRead,
    signing_key: &str,
    max_record_bytes: usize,
    history_limit: usize,
) -> Result<AuditChain> {
    let mut expected_sequence = 1_u64;
    let mut previous_hmac = String::new();
    let mut recent = VecDeque::with_capacity(history_limit.min(4096));
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .context("read admin audit spool")?;
        if read == 0 {
            break;
        }
        if line.len() > max_record_bytes.saturating_add(1) {
            bail!("admin audit spool contains an oversized record");
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            bail!("admin audit spool contains an empty record");
        }
        let event: StoredAdminAuditEvent =
            serde_json::from_slice(&line).context("decode admin audit spool record")?;
        if event.sequence != expected_sequence || event.previous_hmac != previous_hmac {
            bail!("admin audit sequence/hash chain mismatch");
        }
        let unsigned = UnsignedAdminAuditEvent {
            sequence: event.sequence,
            previous_hmac: event.previous_hmac.as_str(),
            payload: &event.payload,
        };
        let canonical =
            serde_json::to_string(&unsigned).context("encode audit verification input")?;
        if !nasa::crypto::hmac_sha256_verify(
            canonical.as_str(),
            signing_key,
            event.hmac_sha256.as_str(),
        ) {
            bail!("admin audit HMAC verification failed");
        }
        expected_sequence = expected_sequence.saturating_add(1);
        previous_hmac = event.hmac_sha256.clone();
        recent.push_back(event);
        while recent.len() > history_limit {
            recent.pop_front();
        }
    }
    Ok(AuditChain {
        next_sequence: expected_sequence,
        previous_hmac,
        recent,
    })
}

/// 固定资源域字符串，避免 serde enum 表现变化污染审计协议。
const fn resource_name(resource: AdminResource) -> &'static str {
    match resource {
        AdminResource::Config => "config",
        AdminResource::Routes => "routes",
        AdminResource::InterfaceGuard => "interface-guard",
        AdminResource::Sentinel => "sentinel",
        AdminResource::Acl => "acl",
        AdminResource::Secrets => "secrets",
        AdminResource::Consumers => "consumers",
        AdminResource::Certs => "certs",
        AdminResource::Cluster => "cluster",
        AdminResource::Cache => "cache",
        AdminResource::Connections => "connections",
        AdminResource::Upstreams => "upstreams",
        AdminResource::Audit => "audit",
    }
}

/// 固定动作字符串。
const fn action_name(action: AdminAction) -> &'static str {
    match action {
        AdminAction::Read => "read",
        AdminAction::DryRun => "dry-run",
        AdminAction::Write => "write",
        AdminAction::EmergencyKill => "emergency-kill",
        AdminAction::Rollback => "rollback",
    }
}

/// 当前 Unix epoch 毫秒；系统时间回拨不会影响 sequence/hash-chain 的单调性。
fn unix_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
