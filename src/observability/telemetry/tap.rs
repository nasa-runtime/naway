//! 审批绑定的本机诊断目录；只保存经过字段白名单处理的有界样本。

mod capture;
mod download;
mod mask;
pub(crate) use capture::Capture;
pub(crate) use download::Permit as DownloadPermit;

use crate::config::GatewaySnapshot;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

/// 诊断范围必须精确到一个物理入口和路由，consumer 只与认证后身份比较。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub proxy: String,
    pub route: String,
    pub consumer: Option<String>,
    pub ttl_seconds: u64,
    pub max_samples: usize,
    pub max_record_bytes: usize,
    pub max_total_bytes: usize,
    pub max_downloads: u32,
    #[serde(default)]
    pub body: Option<BodyPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyPolicy {
    pub mask: Mask,
    pub max_inspect_bytes: usize,
    #[serde(default)]
    pub request_fields: Vec<String>,
    #[serde(default)]
    pub response_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mask {
    Redact,
}

struct Entry {
    id: String,
    request: Request,
    initiator: String,
    approver: Option<String>,
    generation: u64,
    fingerprint: Option<u64>,
    owner: Option<crate::control::ownership::Owner>,
    digest: String,
    expires: Instant,
    samples: Vec<Value>,
    bytes: usize,
    downloads: u32,
    reserved: usize,
    permit: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Default)]
struct Inner {
    entries: BTreeMap<String, Entry>,
    sweeping: bool,
    sequence: u64,
}

#[derive(Default)]
pub(crate) struct Registry {
    inner: Mutex<Inner>,
    snapshot: OnceLock<Weak<ArcSwap<GatewaySnapshot>>>,
    inflight: std::sync::atomic::AtomicUsize,
    downloads: std::sync::atomic::AtomicUsize,
}

impl Registry {
    /// 业务作用：将已完成响应头的固定元信息非阻塞提交给仍有效的精确诊断范围。
    ///
    /// 参数说明：
    /// - `generation`：来自请求快照
    /// - `proxy`：来自请求快照
    /// - `route`：来自请求快照
    /// - `consumer`：是认证后冻结身份
    /// - `method`：是业务执行事实，不传入任意 header、URL 或正文。
    /// - `status`：是业务执行事实，不传入任意 header、URL 或正文。
    /// - `elapsed`：是业务执行事实，不传入任意 header、URL 或正文。
    ///
    /// 返回：只在审批有效且单条、条数和累计字节预算均充足时保存，争用或失权直接跳过。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &self,
        generation: u64,
        proxy: &str,
        route: &str,
        consumer: Option<&str>,
        method: &http::Method,
        status: u16,
        elapsed: Duration,
    ) {
        if method.as_str().len() > 32 {
            return;
        }
        let Ok(snapshot) = self.current() else {
            return;
        };
        if snapshot.version != generation || !enabled(&snapshot) {
            return;
        }
        let Some(mut inner) = self.inner.try_lock() else {
            return;
        };
        Self::expire(&mut inner, &snapshot);
        for entry in inner.entries.values_mut() {
            if entry.approver.is_none()
                || entry.request.body.is_some()
                || entry.request.proxy != proxy
                || entry.request.route != route
                || entry
                    .request
                    .consumer
                    .as_deref()
                    .is_some_and(|selected| Some(selected) != consumer)
                || entry.samples.len() >= entry.request.max_samples
            {
                continue;
            }
            // 固定 head 摘要从未接收认证头、cookie、连接密钥或原始 URI，后续扩展不得透传整张 head。
            let sample = json!({
                "method":method.as_str(),
                "status":status,
                "elapsed_us":elapsed.as_micros().min(u128::from(u64::MAX)) as u64
            });
            let bytes = serde_json::to_vec(&sample).map_or(usize::MAX, |bytes| bytes.len());
            if bytes > entry.request.max_record_bytes
                || bytes > entry.request.max_total_bytes.saturating_sub(entry.bytes)
            {
                continue;
            }
            entry.bytes += bytes;
            entry.samples.push(sample);
        }
    }

    /// 业务作用：把诊断目录绑定到唯一活动快照，不让旧请求或旧审批自行声明当前代。
    ///
    /// 参数说明：
    /// - `snapshot`：是进程发布点；仅保留弱引用。
    ///
    /// 返回：首次绑定成功，重复绑定拒绝。
    pub(crate) fn bind(&self, snapshot: &Arc<ArcSwap<GatewaySnapshot>>) -> anyhow::Result<()> {
        self.snapshot
            .set(Arc::downgrade(snapshot))
            .map_err(|_| anyhow::anyhow!("diagnostics already bound"))
    }

    /// 业务作用：为容量、审批和数据提交读取同一活动配置权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前已发布快照；进程正在退出或未绑定时拒绝。
    fn current(&self) -> anyhow::Result<Arc<GatewaySnapshot>> {
        let source = self
            .snapshot
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| anyhow::anyhow!("diagnostics unavailable"))?;
        Ok(source.load_full())
    }

    /// 业务作用：清除到期、换代或关闭后的所有样本，旧授权不跨 reload 延续。
    ///
    /// 参数说明：
    /// - `inner`：是已持锁目录
    /// - `snapshot`：是当前唯一活动代。
    ///
    /// 返回：退休条目和其样本立即失去目录引用，不留下可下载历史。
    fn expire(inner: &mut Inner, snapshot: &GatewaySnapshot) {
        let now = Instant::now();
        inner.entries.retain(|_, entry| {
            let keep = live(entry, snapshot, now);
            if !keep {
                entry
                    .permit
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            keep
        });
    }

    /// 业务作用：登记限时诊断申请，只保存受限范围，不立即开放采集。
    ///
    /// 参数说明：
    /// - `request`：是显式硬预算
    /// - `initiator`：是已认证且有诊断写权限的主体
    /// - `generation`：绑定认证代。
    ///
    /// 返回：申请元信息和不可变摘要；预算、目标、代际或容量不满足时拒绝。
    pub(crate) fn propose(
        self: &Arc<Self>,
        request: Request,
        initiator: &str,
        generation: u64,
    ) -> anyhow::Result<Value> {
        validate(&request)?;
        let snapshot = self.current()?;
        anyhow::ensure!(
            enabled(&snapshot) && snapshot.version == generation,
            "diagnostics generation changed or disabled"
        );
        anyhow::ensure!(
            snapshot.proxy(&request.proxy).is_some_and(|proxy| proxy
                .router
                .routes()
                .iter()
                .any(|route| route.id == request.route)),
            "diagnostics route not found"
        );
        let owner = snapshot
            .ownership
            .route_owner(&request.proxy, &request.route)
            .cloned();
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        // 全部申请共享固定进程硬门，不允许反复审批或换代叠加内存预算。
        anyhow::ensure!(
            inner.entries.len() < 8,
            "diagnostics session capacity reached"
        );
        inner.sequence = inner
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("diagnostics id capacity reached"))?;
        let id = format!("tap-{}-{}", generation, inner.sequence);
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                generation,
                snapshot.config_fingerprint,
                &owner,
                &request,
                initiator
            ))?)
        );
        let entry = Entry {
            id: id.clone(),
            request,
            initiator: initiator.into(),
            approver: None,
            generation,
            fingerprint: snapshot.config_fingerprint,
            owner,
            digest,
            expires: Instant::now() + Duration::from_secs(60),
            samples: Vec::new(),
            bytes: 0,
            downloads: 0,
            reserved: 0,
            permit: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let result = metadata(&entry);
        inner.entries.insert(id, entry);
        if !inner.sweeping {
            inner.sweeping = true;
            let registry = Arc::downgrade(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let Some(registry) = registry.upgrade() else {
                        return;
                    };
                    let mut inner = registry.inner.lock();
                    match registry.current() {
                        Ok(snapshot) => Self::expire(&mut inner, &snapshot),
                        Err(_) => inner.entries.clear(),
                    }
                    if inner.entries.is_empty() {
                        inner.sweeping = false;
                        return;
                    }
                }
            });
        }
        Ok(result)
    }

    /// 业务作用：由不同主体批准精确摘要，审批成功才开始计时和采样。
    ///
    /// 参数说明：
    /// - `id`：绑定申请
    /// - `digest`：绑定申请
    /// - `approver`：来自当前诊断写权限
    /// - `generation`：绑定本次认证代。
    ///
    /// 返回：唯一审批成功后的元信息；自批、重复、过期或换代不改变状态。
    pub(crate) fn approve(
        &self,
        id: &str,
        digest: &str,
        approver: &str,
        generation: u64,
    ) -> anyhow::Result<Value> {
        let snapshot = self.current()?;
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        anyhow::ensure!(
            snapshot.version == generation,
            "diagnostics generation changed"
        );
        let entry = inner
            .entries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("diagnostics session not found"))?;
        if entry.request.body.is_some() {
            // 一个流只能绑定一套正文白名单；相交范围不能以并列会话重复读取并放大解析预算。
            anyhow::ensure!(
                !inner.entries.values().any(|other| other.id != id
                    && other.approver.is_some()
                    && other.request.body.is_some()
                    && other.request.proxy == entry.request.proxy
                    && other.request.route == entry.request.route
                    && (other.request.consumer.is_none()
                        || entry.request.consumer.is_none()
                        || other.request.consumer == entry.request.consumer)),
                "diagnostics body scope overlaps an active session"
            );
        }
        let entry = inner
            .entries
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("diagnostics session not found"))?;
        anyhow::ensure!(
            entry.digest == digest && entry.initiator != approver && entry.approver.is_none(),
            "diagnostics approval rejected"
        );
        // 到此才授予采集权威；失败不能延长等待期限或清空已使用的下载额度。
        entry.approver = Some(approver.into());
        entry.expires = Instant::now() + Duration::from_secs(entry.request.ttl_seconds);
        entry
            .permit
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(metadata(entry))
    }

    /// 业务作用：只列出当前代有效会话的低敏元信息，不通过列表交付样本。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多八项，过期与退休申请同时被销毁。
    pub(crate) fn list(&self) -> anyhow::Result<Value> {
        let snapshot = self.current()?;
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        Ok(json!({
            "sessions":inner.entries.values().map(metadata).collect::<Vec<_>>()
        }))
    }

    /// 业务作用：在异步审计完成后重新检查交付权威，不能交付已到期或被撤回的副本。
    ///
    /// 参数说明：
    /// - `id`：指向本次已执行动作的精确会话和配置代。
    /// - `generation`：指向本次已执行动作的精确会话和配置代。
    ///
    /// 返回：目录仍存在且授权有效时为真；检查本身不延长 TTL。
    pub(crate) fn available(&self, id: &str, generation: u64) -> bool {
        let Ok(snapshot) = self.current() else {
            return false;
        };
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        snapshot.version == generation && inner.entries.contains_key(id)
    }

    /// 业务作用：撤回待批或活动会话，立即销毁其目录和已采集内容。
    ///
    /// 参数说明：
    /// - `id`：为精确会话
    /// - `generation`：是认证代。
    ///
    /// 返回：成功删除；不存在或换代拒绝，迟到采集不重建目录。
    pub(crate) fn stop(&self, id: &str, generation: u64) -> anyhow::Result<()> {
        let snapshot = self.current()?;
        anyhow::ensure!(
            snapshot.version == generation,
            "diagnostics generation changed"
        );
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        let entry = inner
            .entries
            .remove(id)
            .ok_or_else(|| anyhow::anyhow!("diagnostics session not found"))?;
        entry
            .permit
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// 业务作用：原子扣减下载次数后交付当前有限样本；失败传输也消耗次数。
    ///
    /// 参数说明：
    /// - `id`：为精确会话
    /// - `generation`：是已经认证并审计的活动代。
    ///
    /// 返回：有限 JSON 文档和必须随交付字节持有的名额；未批准、到期、超次或代际漂移拒绝。
    pub(crate) fn download(
        self: &Arc<Self>,
        id: &str,
        generation: u64,
    ) -> anyhow::Result<(Value, DownloadPermit)> {
        // 克隆样本前取得跨会话、跨配置代的名额，慢下载不能通过反复停用会话放大内存。
        let permit = DownloadPermit::acquire(self)?;
        let snapshot = self.current()?;
        anyhow::ensure!(
            snapshot.version == generation,
            "diagnostics generation changed"
        );
        let mut inner = self.inner.lock();
        Self::expire(&mut inner, &snapshot);
        let entry = inner
            .entries
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("diagnostics session not found"))?;
        anyhow::ensure!(
            entry.approver.is_some() && entry.downloads < entry.request.max_downloads,
            "diagnostics download unavailable"
        );
        entry.downloads += 1;
        Ok((
            json!({
                "session":metadata(entry),
                "samples":entry.samples
            }),
            permit,
        ))
    }
}

/// 业务作用：判断活动快照是否显式开放诊断入口。
///
/// 参数说明：
/// - `snapshot`：为已验证配置，不接受请求覆盖。
///
/// 返回：仅显式开启时为真。
pub(crate) fn enabled(snapshot: &GatewaySnapshot) -> bool {
    snapshot
        .telemetry
        .multi_signal
        .as_ref()
        .is_some_and(|cfg| cfg.traffic_tap)
}

/// 业务作用：按固定硬门验证诊断范围和物理存储预算。
///
/// 参数说明：
/// - `request`：是尚未保存的申请。
///
/// 返回：所有字段满足有限合同才成功，不截断越界授权。
fn validate(request: &Request) -> anyhow::Result<()> {
    let name = |value: &str| {
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
    };
    anyhow::ensure!(
        name(&request.proxy)
            && name(&request.route)
            && request.consumer.as_deref().is_none_or(name),
        "invalid diagnostics selector"
    );
    anyhow::ensure!(
        (1..=300).contains(&request.ttl_seconds)
            && (1..=128).contains(&request.max_samples)
            && (256..=4096).contains(&request.max_record_bytes)
            && (request.max_record_bytes..=262144).contains(&request.max_total_bytes)
            && (1..=3).contains(&request.max_downloads),
        "invalid diagnostics budget"
    );
    if let Some(body) = &request.body {
        anyhow::ensure!(
            (1..=65536).contains(&body.max_inspect_bytes)
                && (!body.request_fields.is_empty() || !body.response_fields.is_empty()),
            "invalid diagnostics body budget"
        );
        for fields in [&body.request_fields, &body.response_fields] {
            let mut unique = std::collections::BTreeSet::new();
            anyhow::ensure!(fields.len() <= 16, "too many diagnostics body fields");
            for field in fields {
                let lower = field.to_ascii_lowercase();
                anyhow::ensure!(
                    !field.is_empty()
                        && field.len() <= 64
                        && field
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        && unique.insert(field)
                        && ![
                            "auth",
                            "cookie",
                            "secret",
                            "token",
                            "password",
                            "credential",
                            "private",
                            "key",
                            "certificate",
                            "session"
                        ]
                        .iter()
                        .any(|term| lower.contains(term)),
                    "invalid or sensitive diagnostics body field"
                );
            }
        }
    }
    Ok(())
}

/// 业务作用：把过期、配置换代与显式关闭统一为失权，保证迟到操作不能恢复采集。
///
/// 参数说明：
/// - `entry`：是冻结权威
/// - `snapshot`：是当前配置和单调时间。
/// - `now`：是当前配置和单调时间。
///
/// 返回：只有原始授权仍完全有效才返回真。
fn live(entry: &Entry, snapshot: &GatewaySnapshot, now: Instant) -> bool {
    enabled(snapshot)
        && now < entry.expires
        && snapshot.version == entry.generation
        && snapshot.config_fingerprint == entry.fingerprint
}

/// 业务作用：输出可复核范围和预算，不泄露采集内容或认证凭据。
///
/// 参数说明：
/// - `entry`：是当前有效会话。
///
/// 返回：固定字段元信息和精确摘要。
fn metadata(entry: &Entry) -> Value {
    json!({
        "id":entry.id,
        "digest":entry.digest,
        "generation":entry.generation,
        "owner":entry.owner,
        "request":entry.request,
        "initiator":entry.initiator,
        "approver":entry.approver,
        "state":if entry.approver.is_some(){
            "active"
        }else{
            "pending"
        },
        "remaining_ms":entry.expires.saturating_duration_since(Instant::now()).as_millis(),
        "samples":entry.samples.len(),
        "bytes":entry.bytes,
        "downloads":entry.downloads
    })
}
