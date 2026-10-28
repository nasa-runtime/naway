//! 管理操作持久、防篡改审计与独立工作区查询窗口。
//!
//! 管理写请求与显式 WebDAV 写操作等待落盘与外部 sink 确认，普通代理请求不进入此路径。
//! 每条记录使用 HMAC-SHA256 串起前一条 MAC，启动时从头验证 sequence/chain/MAC，发现
//! 离线修改或重排立即 fail-fast。`Bytes` 同时用于 append 与 HTTP body，外发只增加引用计数。

use std::collections::{BTreeMap, VecDeque};
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
    /// 工作区动作的配置权威和候选摘要；旧平台记录省略此字段，保持原有 HMAC 编码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceAudit>,
    /// Unix epoch 毫秒。
    pub ts_ms: u128,
    /// RBAC principal id。
    pub principal: String,
    /// HTTP method。
    pub method: String,
    /// 不含 query 的管理 API path；文件操作使用固定域路径，不暴露本地资源名。
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkspaceAudit {
    pub binding: crate::control::ownership::Binding,
    pub candidate_sha256: String,
    /// 审批已经授予发布权威的主体；申请阶段为空，后台晋级需继续复验该主体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
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
    workspace_recent: BTreeMap<String, VecDeque<StoredAdminAuditEvent>>,
}

impl AuditChain {
    /// 业务作用：为每个完整归属保留独立审计尾窗，单域连续写入不能挤掉其它活动域的记录。
    ///
    /// 参数说明：
    /// - `event`：是已落盘或已验证事件
    /// - `history_limit`：限制平台窗口和单域窗口。
    ///
    /// 返回：更新有界内存索引；完整历史仍以持久 hash-chain 为准。
    fn retain(&mut self, event: StoredAdminAuditEvent, history_limit: usize) {
        if let Some(workspace) = event.payload.workspace.as_ref() {
            let key = workspace.binding.owner.namespace();
            if !self.workspace_recent.contains_key(&key) && self.workspace_recent.len() >= 256 {
                // 只有平台能新建归属；长期更换 tenant 后退休最久未写入的域，避免旧域目录无界积累。
                if let Some(oldest) = self
                    .workspace_recent
                    .iter()
                    .min_by_key(|(_, records)| records.back().map(|event| event.sequence))
                    .map(|(key, _)| key.clone())
                {
                    self.workspace_recent.remove(&oldest);
                }
            }
            let own = self.workspace_recent.entry(key).or_default();
            own.push_back(event.clone());
            while own.len() > history_limit.min(128) {
                own.pop_front();
            }
        }
        self.recent.push_back(event);
        while self.recent.len() > history_limit {
            self.recent.pop_front();
        }
    }
}

impl AdminAuditLog {
    /// 业务作用：打开并完整验证已有 spool；任一坏行/MAC 失配会阻止管理面启动。
    ///
    /// 参数说明：
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
    /// 参数说明：
    /// - `config`：是候选快照已解密且完成边界校验的审计计划。
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
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；后续写操作失败闭合，直到候选代提交或取消。
    pub fn begin_transition(&self) {
        self.transitioning.store(true, Ordering::Release);
    }

    /// 业务作用：取消尚未发布的审计换代门禁，恢复旧代写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值。
    pub fn cancel_transition(&self) {
        self.transitioning.store(false, Ordering::Release);
    }

    /// 业务作用：在已发布快照后切换审计 owner，并等待已进入旧代的唯一写入结束。
    ///
    /// 参数说明：
    /// - `candidate`：是通过 [`Self::prepare_replacement`] 构建的候选代。
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
/// 参数说明：
/// - `config`：是已解析的 spool、签名与远端 sink 计划。
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
    /// 业务作用：追加一条审计记录：本地 O_APPEND + 可选 fsync 成功后，再等待外部 sink 2xx。
    ///
    /// 写动作应在副作用前先写 `attempt`；任何错误均 fail-closed。`completed` 记录响应状态。
    ///
    /// 参数说明：
    /// - `input`: 已通过认证/RBAC 的小型审计字段，不含敏感 header/query 原文。
    pub async fn record(&self, input: AdminAuditInput<'_>) -> Result<()> {
        self.record_scoped(input, None).await
    }

    /// 业务作用：在同一持久审计链中绑定工作区 owner、权限图与候选摘要，拒绝跨域审计冒名。
    ///
    /// 参数说明：
    /// - `input`：已认证操作元数据。
    /// - `workspace`：仅由服务端当前归属图和冻结候选产生的绑定。
    ///
    /// 返回：本地和配置要求的外部收据成功才允许调用方继续副作用；失败闭合。
    pub async fn record_scoped(
        &self,
        input: AdminAuditInput<'_>,
        workspace: Option<WorkspaceAudit>,
    ) -> Result<()> {
        let payload = AdminAuditPayload {
            workspace,
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
        self.append_payload(payload, false).await
    }

    /// 业务作用：持久化已冻结身份的文件写事实，调用方取消不能把 hash-chain 留在半条记录。
    ///
    /// 参数说明：
    /// - `payload`：服务端构造的低敏操作摘要、阶段和配置权威。
    ///
    /// 返回：完整持久确认后成功；容量、审计关闭或存储失败均拒绝继续业务写入。
    #[cfg(feature = "webdav")]
    pub(crate) async fn record_webdav(&self, payload: AdminAuditPayload) -> Result<()> {
        self.record_required(payload).await
    }

    /// 业务作用：在敏感外部副作用前取得持久审计收据，调用方取消不截断正在追加的 hash-chain。
    ///
    /// 参数说明：
    /// - `payload`：调用模块基于当前认证身份与配置权威生成的低敏操作事实。
    ///
    /// 返回：完整持久确认后成功；审计关闭、未同步刷盘、容量不足或存储失败均拒绝后续副作用。
    #[cfg(any(
        feature = "webdav",
        feature = "xds-server",
        all(feature = "admin-operations-workflow-pgsql", feature = "node-actions")
    ))]
    pub(crate) async fn record_required(&self, payload: AdminAuditPayload) -> Result<()> {
        static CAPACITY: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit = CAPACITY
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64)))
            .clone()
            .try_acquire_owned()
            .context("durable audit capacity reached")?;
        let audit = self.clone();
        // 只将有界审计提交交给独立任务；取消等待不会取消落盘，任务本身没有文件业务执行权。
        tokio::spawn(async move {
            let _permit = permit;
            audit.append_payload(payload, true).await
        })
        .await
        .context("durable audit worker unavailable")?
    }

    /// 业务作用：串行提交所有获准的审计载荷，保持落盘、内存链推进、远端确认的唯一顺序。
    ///
    /// 参数说明：
    /// - `payload`：不含凭据或资源原文的固定结构。
    /// - `required`：为 true 时审计关闭或未配置持久刷盘都不能降级成功。
    ///
    /// 返回：本地和可选远端确认全部完成；本地成功后即使远端失败也保留已推进的链。
    async fn append_payload(&self, payload: AdminAuditPayload, required: bool) -> Result<()> {
        if self.transitioning.load(Ordering::Acquire) {
            bail!("admin audit generation is transitioning");
        }
        // 换代与记录共用写门，确保旧 owner 不会在新代验证完 sequence 后迟到追加。
        let _write_gate = self.write_gate.lock().await;
        if self.transitioning.load(Ordering::Acquire) {
            bail!("admin audit generation is transitioning");
        }
        let Some(inner) = self.active.load_full() else {
            anyhow::ensure!(!required, "required audit is disabled");
            return Ok(());
        };
        anyhow::ensure!(
            !required || inner.config.fsync,
            "required audit needs durable sync"
        );
        // 管理动作与敏感外部副作用共用此锁，串行确认 sequence 后才允许调用方继续执行。
        let mut chain = inner.chain.lock().await;
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
        // 编码缓冲区由 Bytes 直接接管；后续 HTTP body 克隆只增加引用计数，避免复制审计正文。
        let encoded = Bytes::from(encoded);
        append_local(&inner, encoded.as_ref()).await?;

        // 本地 append 成功后必须推进 chain，即使远端失败；否则下一次会与磁盘 sequence 分叉。
        chain.next_sequence = chain.next_sequence.saturating_add(1);
        chain.previous_hmac = stored.hmac_sha256.clone();
        chain.retain(stored, inner.config.history_limit);
        if let (Some(client), Some(endpoint)) = (&inner.client, &inner.config.endpoint) {
            send_remote(&inner, client, endpoint.as_ref(), encoded).await?;
        }
        Ok(())
    }

    /// 业务作用：返回内存中的已验证尾部窗口；完整记录保留在 spool/外部 sink。
    pub async fn snapshot(&self) -> Vec<StoredAdminAuditEvent> {
        let Some(inner) = self.active.load_full() else {
            return Vec::new();
        };
        let events = inner.chain.lock().await.recent.iter().cloned().collect();
        events
    }

    /// 业务作用：从独立尾窗查询完整 owner 的审计，不以全平台最近事件过滤冒充域内保留。
    ///
    /// 参数说明：
    /// - `owner`：来自当前已授权配置。
    ///
    /// 返回：至多 128 条已验证事件；同名 workspace 更换 tenant/environment 后不能读取旧域。
    pub async fn workspace_snapshot(
        &self,
        owner: &crate::control::ownership::Owner,
    ) -> Vec<StoredAdminAuditEvent> {
        let Some(inner) = self.active.load_full() else {
            return Vec::new();
        };
        let chain = inner.chain.lock().await;
        chain
            .workspace_recent
            .get(&owner.namespace())
            .into_iter()
            .flatten()
            .filter(|event| {
                event
                    .payload
                    .workspace
                    .as_ref()
                    .is_some_and(|scope| scope.binding.owner == *owner)
            })
            .cloned()
            .collect()
    }
}

/// 业务作用：O_APPEND 写入一条 JSON 与换行；可选 sync_data 把控制面成功边界推进到持久介质。
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

/// 业务作用：把与本地 append 共用的 `Bytes` 发往外部持久 sink，并有界排空响应以复用连接。
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

/// 业务作用：启动时流式验证完整审计链，并重建平台和各归属域的有界尾窗。
///
/// 参数说明：
/// - `reader`：提供 spool
/// - `signing_key`：验证链
/// - `max_record_bytes`：限制单行
/// - `history_limit`：限制查询窗口。
///
/// 返回：完整链合法时返回可续写状态；超限、断链或签名不符时拒绝启动。
fn verify_spool(
    mut reader: impl BufRead,
    signing_key: &str,
    max_record_bytes: usize,
    history_limit: usize,
) -> Result<AuditChain> {
    let mut expected_sequence = 1_u64;
    let mut previous_hmac = String::new();
    let mut chain = AuditChain {
        next_sequence: 1,
        previous_hmac: String::new(),
        recent: VecDeque::with_capacity(history_limit.min(4096)),
        workspace_recent: BTreeMap::new(),
    };
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = std::io::Read::take(&mut reader, max_record_bytes.saturating_add(2) as u64)
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
        chain.retain(event, history_limit);
    }
    chain.next_sequence = expected_sequence;
    chain.previous_hmac = previous_hmac;
    Ok(chain)
}

/// 业务作用：固定资源域字符串，避免 serde enum 表现变化污染审计协议。
///
/// 参数说明：
/// - resource：已由授权路由确定的有限管理资源。
///
/// 返回：与已有审计检索一致的稳定资源名。
pub(super) const fn resource_name(resource: AdminResource) -> &'static str {
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
        AdminResource::Diagnostics => "diagnostics",
    }
}

/// 业务作用：固定动作字符串。
const fn action_name(action: AdminAction) -> &'static str {
    match action {
        AdminAction::Read => "read",
        AdminAction::DryRun => "dry-run",
        AdminAction::Write => "write",
        AdminAction::EmergencyKill => "emergency-kill",
        AdminAction::Rollback => "rollback",
    }
}

/// 业务作用：当前 Unix epoch 毫秒；系统时间回拨不会影响 sequence/hash-chain 的单调性。
fn unix_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
