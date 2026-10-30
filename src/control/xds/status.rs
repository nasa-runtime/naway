//! ADS 状态与实际发布共用代际权威，常驻读者始终观察当前代。

use super::{fingerprint_hex, truncate_error, unix_timestamp_seconds, xds_type_label};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

/// xDS task 对 readiness/admin 暴露的低基数状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XdsConnectionState {
    /// 尚未连通或首次同步失败。
    Disconnected = 0,
    /// ADS stream 已建立，等待第一份可接受 EDS。
    Syncing = 1,
    /// 最近完整候选已发布并接受。
    Active = 2,
    /// 已有 LKG，但 stream 断开或最新 response 被 NACK。
    Degraded = 3,
}

impl XdsConnectionState {
    /// 业务作用：把原子状态值恢复成封闭枚举，避免损坏值影响 readiness 判断。
    ///
    /// 参数说明：
    /// - `raw`：是进程内 `AtomicU8` 当前值。
    ///
    /// 返回：已知值对应状态；未知值保守解释为 `Disconnected`。
    fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Syncing,
            2 => Self::Active,
            3 => Self::Degraded,
            _ => Self::Disconnected,
        }
    }
}

/// xDS 运行时可观测快照；字符串在 admin 低频读取时才 clone。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XdsStatusSnapshot {
    /// 当前连接/同步状态。
    pub state: XdsConnectionState,
    /// 当前任务代是否至少发布过一份完整候选。
    pub ready: bool,
    /// 当前 ADS HTTP/2 stream 是否仍连接。
    pub stream_up: bool,
    /// 最近接受的 opaque version；warming 候选可能尚未成为活动快照。
    pub accepted_version: String,
    /// 各受支持 type 已 ACK 的独立 opaque version，键为受支持资源类型的固定标签。
    pub accepted_versions: BTreeMap<String, String>,
    /// 最近 response nonce。
    pub last_nonce: String,
    /// 各受支持 type 最近 ACK/NACK nonce，键为受支持资源类型的固定标签。
    pub last_nonces: BTreeMap<String, String>,
    /// 最近失败摘要，不含证书或资源原文。
    pub last_error: Option<String>,
    /// 当前 accepted 候选尚未闭合的低敏资源名，active 时为空。
    pub warming_dependencies: BTreeSet<String>,
    /// 当前已发布 native xDS 内容 SHA-256；不含秘密，也不作为认证凭据。
    pub applied_fingerprint: Option<String>,
    /// 本进程已接受响应的累计数量。
    pub ack_total: u64,
    /// 本进程已拒绝响应的累计数量。
    pub nack_total: u64,
    /// ADS 重连次数。
    pub reconnect_total: u64,
    /// 内容未变化、仅 ACK 新 version/nonce 的 response 数。
    pub duplicate_total: u64,
    /// 最近收到任意 response 的 Unix 秒时间戳。
    pub last_received_timestamp: u64,
    /// 最近成功发布 EDS 的 Unix 秒时间戳。
    pub last_applied_timestamp: u64,
    /// 当前 active xDS resource 总数。
    pub active_resources: u64,
    /// 当前 active 资源按固定 eds/cds/rds type 的数量。
    pub active_resources_by_type: BTreeMap<String, u64>,
    /// 当前 translate/apply 队列深度；SotW 串行实现只能为 0 或 1。
    pub apply_queue_depth: u64,
    /// 因校验或预算拒绝的 response 编码字节累计值。
    pub rejected_bytes_total: u64,
    /// 依赖闭包在无新 response 时达到 warming deadline 的周期数。
    pub warming_timeout_total: u64,
    /// 因 Delta Resource.ttl 到期而撤销的资源数。
    pub ttl_expired_total: u64,
}

#[derive(Default)]
struct XdsStatusDetail {
    accepted_version: String,
    last_nonce: String,
    last_error: Option<String>,
    accepted_fingerprint: Option<[u8; 32]>,
    accepted_versions: BTreeMap<String, String>,
    last_nonces: BTreeMap<String, String>,
    active_resources_by_type: BTreeMap<String, u64>,
    warming_dependencies: BTreeSet<String>,
    applied_fingerprint: Option<String>,
}

/// 管理读者共享当前事实；后台句柄另持独立任务令牌，旧任务不能覆盖新代状态。
pub struct XdsStatus {
    shared: Arc<Shared>,
    owner: Arc<()>,
}

struct Shared {
    state: AtomicU8,
    ready: AtomicBool,
    stream_up: AtomicBool,
    ack_total: AtomicU64,
    nack_total: AtomicU64,
    reconnect_total: AtomicU64,
    duplicate_total: AtomicU64,
    last_received_timestamp: AtomicU64,
    last_applied_timestamp: AtomicU64,
    active_resources: AtomicU64,
    apply_queue_depth: AtomicU64,
    rejected_bytes_total: AtomicU64,
    warming_timeout_total: AtomicU64,
    ttl_expired_total: AtomicU64,
    detail: RwLock<XdsStatusDetail>,
    authority: Mutex<Arc<()>>,
}

impl Default for XdsStatus {
    /// 业务作用：创建尚未取得任何 xDS 权威版本的 fail-closed 状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`Disconnected` 且 `ready=false` 的状态句柄。
    fn default() -> Self {
        let owner = Arc::new(());
        let shared = Shared {
            state: AtomicU8::new(XdsConnectionState::Disconnected as u8),
            ready: AtomicBool::new(false),
            stream_up: AtomicBool::new(false),
            ack_total: AtomicU64::new(0),
            nack_total: AtomicU64::new(0),
            reconnect_total: AtomicU64::new(0),
            duplicate_total: AtomicU64::new(0),
            last_received_timestamp: AtomicU64::new(0),
            last_applied_timestamp: AtomicU64::new(0),
            active_resources: AtomicU64::new(0),
            apply_queue_depth: AtomicU64::new(0),
            rejected_bytes_total: AtomicU64::new(0),
            warming_timeout_total: AtomicU64::new(0),
            ttl_expired_total: AtomicU64::new(0),
            detail: RwLock::new(XdsStatusDetail::default()),
            authority: Mutex::new(owner.clone()),
        };
        Self {
            shared: Arc::new(shared),
            owner,
        }
    }
}

impl XdsStatus {
    /// 业务作用：撤销上一 ADS 代的 readiness 与详情权威，防止新身份复用旧 ACK。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本代专用写入句柄；常驻读者共享最新事实与累计计数，旧句柄失去修改权。
    pub(super) fn begin_generation(&self) -> Arc<Self> {
        let owner = Arc::new(());
        let mut active = self
            .shared
            .authority
            .lock()
            .expect("xDS authority lock poisoned");
        // 先撤销旧令牌，再清空本代事实；旧事件只有通过同一串行门才可更新状态。
        *active = owner.clone();
        self.shared.ready.store(false, Ordering::Release);
        self.shared.stream_up.store(false, Ordering::Release);
        self.shared.active_resources.store(0, Ordering::Release);
        self.shared.apply_queue_depth.store(0, Ordering::Release);
        self.shared
            .last_received_timestamp
            .store(0, Ordering::Release);
        self.shared
            .last_applied_timestamp
            .store(0, Ordering::Release);
        *self
            .shared
            .detail
            .write()
            .expect("xDS status lock poisoned") = XdsStatusDetail::default();
        self.shared
            .state
            .store(XdsConnectionState::Disconnected as u8, Ordering::Release);
        Arc::new(Self {
            shared: self.shared.clone(),
            owner,
        })
    }

    /// 业务作用：判断 require_xds 启动门是否已由当前任务代发布的完整候选打开。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前代至少成功应用过一次为真；同代断线保留 LKG，配置换代重新等待证明。
    pub fn ready(&self) -> bool {
        self.shared.ready.load(Ordering::Acquire)
    }

    /// 业务作用：提供一致的 admin/metrics 低频快照，不暴露 protobuf 或秘密材料。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前状态、LKG version/nonce、错误摘要和累计 ACK/NACK/reconnect 计数。
    pub fn snapshot(&self) -> XdsStatusSnapshot {
        let _authority = self
            .shared
            .authority
            .lock()
            .expect("xDS authority lock poisoned");
        let detail = self.shared.detail.read().expect("xDS status lock poisoned");
        XdsStatusSnapshot {
            state: XdsConnectionState::from_u8(self.shared.state.load(Ordering::Acquire)),
            ready: self.ready(),
            stream_up: self.shared.stream_up.load(Ordering::Acquire),
            accepted_version: detail.accepted_version.clone(),
            accepted_versions: detail.accepted_versions.clone(),
            last_nonce: detail.last_nonce.clone(),
            last_nonces: detail.last_nonces.clone(),
            last_error: detail.last_error.clone(),
            warming_dependencies: detail.warming_dependencies.clone(),
            applied_fingerprint: detail.applied_fingerprint.clone(),
            ack_total: self.shared.ack_total.load(Ordering::Relaxed),
            nack_total: self.shared.nack_total.load(Ordering::Relaxed),
            reconnect_total: self.shared.reconnect_total.load(Ordering::Relaxed),
            duplicate_total: self.shared.duplicate_total.load(Ordering::Relaxed),
            last_received_timestamp: self.shared.last_received_timestamp.load(Ordering::Relaxed),
            last_applied_timestamp: self.shared.last_applied_timestamp.load(Ordering::Relaxed),
            active_resources: self.shared.active_resources.load(Ordering::Relaxed),
            active_resources_by_type: detail.active_resources_by_type.clone(),
            apply_queue_depth: self.shared.apply_queue_depth.load(Ordering::Relaxed),
            rejected_bytes_total: self.shared.rejected_bytes_total.load(Ordering::Relaxed),
            warming_timeout_total: self.shared.warming_timeout_total.load(Ordering::Relaxed),
            ttl_expired_total: self.shared.ttl_expired_total.load(Ordering::Relaxed),
        }
    }

    /// 业务作用：记录 stream 已建立但尚未取得首份可用配置的同步态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；已有 LKG 时保持 degraded 语义，不假装最新连接已经 active。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_syncing(&self) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        self.shared.stream_up.store(true, Ordering::Release);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：在完整 EDS 已原子发布后登记 ACK 对应的 LKG 权威版本。
    ///
    /// 参数说明：
    /// - `version`：来自已校验 response
    /// - `nonce`：来自已校验 response
    /// - `resource_count`：是 active EDS 资源数
    /// - `fingerprint`：是已发布 native 内容摘要。
    ///
    /// 返回：无；先写详情再开放 readiness，读者不会看到 ready=true 的空版本。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_accepted(
        &self,
        version: &str,
        nonce: &str,
        resource_count: usize,
        fingerprint: [u8; 32],
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            detail.accepted_version = version.to_owned();
            detail.last_nonce = nonce.to_owned();
            detail
                .accepted_versions
                .insert("eds".to_owned(), version.to_owned());
            detail
                .last_nonces
                .insert("eds".to_owned(), nonce.to_owned());
            detail.last_error = None;
            detail.accepted_fingerprint = Some(fingerprint);
            detail.warming_dependencies.clear();
            detail.applied_fingerprint = Some(fingerprint_hex(&fingerprint));
            detail
                .active_resources_by_type
                .insert("eds".to_owned(), resource_count as u64);
        }
        self.shared.ack_total.fetch_add(1, Ordering::Relaxed);
        self.shared
            .active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.shared
            .last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.shared.ready.store(true, Ordering::Release);
        self.shared
            .state
            .store(XdsConnectionState::Active as u8, Ordering::Release);
    }

    /// 业务作用：记录被拒 response，但保留先前已 ACK 的 LKG 与启动门状态。
    ///
    /// 参数说明：
    /// - `nonce`：标识被拒 response
    /// - `error`：是有界、去敏错误摘要
    /// - `response_bytes`：用于累计受控拒绝流量。
    ///
    /// 返回：无；从未成功同步时保持 syncing，否则进入 degraded。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_rejected(&self, nonce: &str, error: &str, response_bytes: usize) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            detail.last_nonce = nonce.to_owned();
            detail
                .last_nonces
                .insert("eds".to_owned(), nonce.to_owned());
            detail.last_error = Some(truncate_error(error));
        }
        self.shared.nack_total.fetch_add(1, Ordering::Relaxed);
        self.shared
            .rejected_bytes_total
            .fetch_add(response_bytes as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录 ADS 断线并保留已接受 LKG，防止控制面瞬断清空业务端点。
    ///
    /// 参数说明：
    /// - `error`：是连接或 stream 失败摘要。
    ///
    /// 返回：无；首份 EDS 前回到 disconnected，已有 LKG 后进入 degraded。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_disconnected(&self, error: &str) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        self.shared.stream_up.store(false, Ordering::Release);
        self.shared
            .detail
            .write()
            .expect("xDS status lock poisoned")
            .last_error = Some(truncate_error(error));
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Disconnected
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：读取当前 LKG version，供新 stream 初始 DiscoveryRequest 恢复 SotW 会话。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最近成功应用的 opaque version；尚无 LKG 时为空。
    pub(super) fn accepted_version(&self) -> String {
        self.shared
            .detail
            .read()
            .expect("xDS status lock poisoned")
            .accepted_version
            .clone()
    }

    /// 业务作用：判断 native EDS 内容是否与当前 active LKG 相同，避免版本心跳触发无意义 RCU 发布。
    ///
    /// 参数说明：
    /// - `fingerprint`：是转换后按服务/实例规范排序的内容摘要。
    ///
    /// 返回：已有 active 内容且摘要一致时返回 true；首次同步返回 false。
    pub(super) fn content_unchanged(&self, fingerprint: &[u8; 32]) -> bool {
        self.shared
            .detail
            .read()
            .expect("xDS status lock poisoned")
            .accepted_fingerprint
            .as_ref()
            == Some(fingerprint)
    }

    /// 业务作用：ACK 内容未变化的新 version/nonce，但不伪造一次新的数据面 apply 时间。
    ///
    /// 参数说明：
    /// - `version`：是本轮 response
    /// - `nonce`：是本轮 response
    /// - `resource_count`：用于保持 active gauge。
    ///
    /// 返回：无；更新控制流 LKG version、ACK/duplicate 计数，保留原 applied timestamp。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_duplicate(&self, version: &str, nonce: &str, resource_count: usize) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            detail.accepted_version = version.to_owned();
            detail.last_nonce = nonce.to_owned();
            detail
                .accepted_versions
                .insert("eds".to_owned(), version.to_owned());
            detail
                .last_nonces
                .insert("eds".to_owned(), nonce.to_owned());
            detail.last_error = None;
            detail.warming_dependencies.clear();
            detail
                .active_resources_by_type
                .insert("eds".to_owned(), resource_count as u64);
        }
        self.shared.ack_total.fetch_add(1, Ordering::Relaxed);
        self.shared.duplicate_total.fetch_add(1, Ordering::Relaxed);
        self.shared
            .active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.shared.ready.store(true, Ordering::Release);
        self.shared
            .state
            .store(XdsConnectionState::Active as u8, Ordering::Release);
    }

    /// 业务作用：登记已从 gRPC stream 收到一份完整 response，供故障时判断控制面新鲜度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；只更新低基数时间戳，不改变 accepted/applied 状态。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_received(&self) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        self.shared
            .last_received_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
    }

    /// 业务作用：读取指定 resource type 的 accepted version，供重连恢复独立 SotW 会话。
    ///
    /// 参数说明：
    /// - `type_url`：是 EDS/CDS/RDS 规范 URL。
    ///
    /// 返回：该 type 最近 ACK version；尚未接受时为空。
    pub(super) fn accepted_version_for(&self, type_url: &str) -> String {
        self.shared
            .detail
            .read()
            .expect("xDS status lock poisoned")
            .accepted_versions
            .get(xds_type_label(type_url))
            .cloned()
            .unwrap_or_default()
    }

    /// 业务作用：记录 CDS/RDS/EDS 候选已经 ACK，并按依赖闭包是否发布更新 readiness/LKG 状态。
    ///
    /// 参数说明：
    /// - `type_url`：标识本轮
    /// - `version`：标识本轮
    /// - `nonce`：标识本轮
    /// - `active_resources`：仅在完整闭包已发布时 携带固定 type 计数
    /// - `applied_fingerprint`：是已发布 native 内容摘要
    /// - `missing`：非空表示 合法候选仍在 warming，旧 active 必须继续服务。
    ///
    /// 返回：无；active 只在 Snapshot 已发布后开放，warming 不会伪造 applied 时间。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_policy_accepted(
        &self,
        type_url: &str,
        version: &str,
        nonce: &str,
        active_resources: Option<&BTreeMap<String, u64>>,
        applied_fingerprint: Option<&[u8; 32]>,
        missing: Option<&BTreeSet<String>>,
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            let label = xds_type_label(type_url).to_owned();
            detail
                .accepted_versions
                .insert(label.clone(), version.to_owned());
            detail.last_nonces.insert(label, nonce.to_owned());
            detail.accepted_version = version.to_owned();
            detail.last_nonce = nonce.to_owned();
            detail.warming_dependencies = missing.cloned().unwrap_or_default();
            if let Some(fingerprint) = applied_fingerprint {
                detail.accepted_fingerprint = Some(*fingerprint);
                detail.applied_fingerprint = Some(fingerprint_hex(fingerprint));
            }
            detail.last_error = missing.map(|names| {
                truncate_error(&format!(
                    "xDS dependency warming: {}",
                    names.iter().cloned().collect::<Vec<_>>().join(",")
                ))
            });
        }
        self.shared.ack_total.fetch_add(1, Ordering::Relaxed);
        if let Some(active_resources) = active_resources {
            let total = active_resources.values().copied().sum::<u64>();
            self.shared
                .detail
                .write()
                .expect("xDS status lock poisoned")
                .active_resources_by_type = active_resources.clone();
            self.shared.active_resources.store(total, Ordering::Relaxed);
            self.shared
                .last_applied_timestamp
                .store(unix_timestamp_seconds(), Ordering::Relaxed);
            self.shared.ready.store(true, Ordering::Release);
            self.shared
                .state
                .store(XdsConnectionState::Active as u8, Ordering::Release);
        } else {
            let state = if self.ready() {
                XdsConnectionState::Degraded
            } else {
                XdsConnectionState::Syncing
            };
            self.shared.state.store(state as u8, Ordering::Release);
        }
    }

    /// 业务作用：按 resource type 记录 NACK nonce，同时保持该 type 旧 accepted version 与全局 LKG。
    ///
    /// 参数说明：
    /// - `type_url`：被拒绝的 xDS 资源类型 URL。
    /// - `nonce`：被拒绝响应的 nonce。
    /// - `error`：候选校验或构建失败原因。
    /// - `response_bytes`：被拒绝响应的 wire 字节数。
    ///
    /// 返回：无；只推进拒绝观测，不开放 readiness、不覆盖已发布 Snapshot。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_policy_rejected(
        &self,
        type_url: &str,
        nonce: &str,
        error: &str,
        response_bytes: usize,
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            detail.last_nonce = nonce.to_owned();
            detail
                .last_nonces
                .insert(xds_type_label(type_url).to_owned(), nonce.to_owned());
            detail.last_error = Some(truncate_error(error));
        }
        self.shared.nack_total.fetch_add(1, Ordering::Relaxed);
        self.shared
            .rejected_bytes_total
            .fetch_add(response_bytes as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录一轮合法但依赖长期不闭合的 warming 超时，不把它伪造成资源 NACK 或清空 LKG。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；首次同步保持 syncing，已有 LKG 保持 ready 并进入 degraded。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_warming_timeout(&self) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        self.shared
            .detail
            .write()
            .expect("xDS status lock poisoned")
            .last_error =
            Some("xDS dependency warming deadline exceeded; retaining prior LKG".to_owned());
        self.shared
            .warming_timeout_total
            .fetch_add(1, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录 Delta TTL 已在无控制面 response 时真实撤销并发布，保持 accepted version/nonce 不变。
    ///
    /// 参数说明：
    /// - `expired`：是本轮撤销资源数
    /// - `resource_count`：是发布后的 EDS 数
    /// - `fingerprint`：是发布后的 native 内容摘要。
    ///
    /// 返回：无；成功 publish 后保持/开放 ready；stream 在线为 active，断线期间保持 degraded。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_eds_ttl_applied(
        &self,
        expired: usize,
        resource_count: usize,
        fingerprint: [u8; 32],
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        let stream_up = self.shared.stream_up.load(Ordering::Acquire);
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            if stream_up {
                detail.last_error = None;
            }
            detail.accepted_fingerprint = Some(fingerprint);
            detail.applied_fingerprint = Some(fingerprint_hex(&fingerprint));
            detail.warming_dependencies.clear();
            detail
                .active_resources_by_type
                .insert("eds".to_owned(), resource_count as u64);
        }
        self.shared
            .ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        self.shared
            .active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.shared
            .last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.shared.ready.store(true, Ordering::Release);
        let state = if stream_up {
            XdsConnectionState::Active
        } else {
            XdsConnectionState::Degraded
        };
        self.shared.state.store(state as u8, Ordering::Release);
    }

    /// 业务作用：记录 TTL 已撤销 accepted 候选但首次依赖仍不完整，不开放 readiness 或伪造 apply。
    ///
    /// 参数说明：
    /// - `expired`：是撤销数
    /// - `missing`：是撤销后仍未取得首次证据的资源名。
    ///
    /// 返回：无；保留旧 LKG（若有），状态为 syncing/degraded，并累计 TTL 撤销观测。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_ttl_warming(&self, expired: usize, missing: &BTreeSet<String>) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            detail.warming_dependencies = missing.clone();
            detail.last_error = Some(truncate_error(&format!(
                "xDS TTL expired while dependencies are warming: {}",
                missing.iter().cloned().collect::<Vec<_>>().join(",")
            )));
        }
        self.shared
            .ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.shared.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：ACK 只更新 per-resource version/TTL、native 内容未变化的 Delta response，避免无意义发布。
    ///
    /// 参数说明：
    /// - `type_url`：标识本轮控制消息；system version 仅用于诊断。
    /// - `system_version`：标识本轮控制消息；system version 仅用于诊断。
    /// - `nonce`：标识本轮控制消息；system version 仅用于诊断。
    ///
    /// 返回：无；推进该 type 的 ACK/nonce 与 duplicate 计数，保留当前 active/warming 状态和错误。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_delta_duplicate(&self, type_url: &str, system_version: &str, nonce: &str) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            let label = xds_type_label(type_url).to_owned();
            detail
                .accepted_versions
                .insert(label.clone(), system_version.to_owned());
            detail.last_nonces.insert(label, nonce.to_owned());
            detail.accepted_version = system_version.to_owned();
            detail.last_nonce = nonce.to_owned();
        }
        self.shared.ack_total.fetch_add(1, Ordering::Relaxed);
        self.shared.duplicate_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：ACK 已恢复完整依赖但 native fingerprint 等于当前 LKG 的 Delta response，解除 warming 而不重复 publish。
    ///
    /// 参数说明：
    /// - `type_url`：是控制身份
    /// - `system_version`：是控制身份
    /// - `nonce`：是控制身份
    /// - `resources`：是现有 active 计数
    /// - `fingerprint`：必须等于当前已发布内容。
    ///
    /// 返回：无；更新 ACK/duplicate 与 cache 收敛状态，保留原 last_applied_timestamp。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_policy_duplicate(
        &self,
        type_url: &str,
        system_version: &str,
        nonce: &str,
        resources: &BTreeMap<String, u64>,
        fingerprint: [u8; 32],
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            let label = xds_type_label(type_url).to_owned();
            detail
                .accepted_versions
                .insert(label.clone(), system_version.to_owned());
            detail.last_nonces.insert(label, nonce.to_owned());
            detail.accepted_version = system_version.to_owned();
            detail.last_nonce = nonce.to_owned();
            detail.last_error = None;
            detail.warming_dependencies.clear();
            detail.accepted_fingerprint = Some(fingerprint);
            detail.applied_fingerprint = Some(fingerprint_hex(&fingerprint));
            detail.active_resources_by_type = resources.clone();
        }
        self.shared.ack_total.fetch_add(1, Ordering::Relaxed);
        self.shared.duplicate_total.fetch_add(1, Ordering::Relaxed);
        self.shared
            .active_resources
            .store(resources.values().copied().sum(), Ordering::Relaxed);
        self.shared.ready.store(true, Ordering::Release);
        self.shared
            .state
            .store(XdsConnectionState::Active as u8, Ordering::Release);
    }

    /// 业务作用：记录跨 type Delta TTL removal 已通过 single-writer 发布，不修改任何 response version/nonce。
    ///
    /// 参数说明：
    /// - `expired`：是撤销资源数
    /// - `resources`：是新 active 固定 type 计数
    /// - `fingerprint`：是已发布 CDS/RDS/EDS 闭包摘要。
    ///
    /// 返回：无；更新 applied 事实、TTL 计数与 readiness；断线时保持 degraded，控制流身份不变。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_policy_ttl_applied(
        &self,
        expired: usize,
        resources: &BTreeMap<String, u64>,
        fingerprint: [u8; 32],
    ) {
        // 旧网络事件不得覆盖新代状态，令牌检查与实际写入共用一个不可中断的同步区间。
        let Some(_authority) = self.current_authority() else {
            return;
        };
        let stream_up = self.shared.stream_up.load(Ordering::Acquire);
        {
            let mut detail = self
                .shared
                .detail
                .write()
                .expect("xDS status lock poisoned");
            if stream_up {
                detail.last_error = None;
            }
            detail.warming_dependencies.clear();
            detail.accepted_fingerprint = Some(fingerprint);
            detail.applied_fingerprint = Some(fingerprint_hex(&fingerprint));
            detail.active_resources_by_type = resources.clone();
        }
        self.shared
            .ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        self.shared
            .active_resources
            .store(resources.values().copied().sum(), Ordering::Relaxed);
        self.shared
            .last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.shared.ready.store(true, Ordering::Release);
        let state = if stream_up {
            XdsConnectionState::Active
        } else {
            XdsConnectionState::Degraded
        };
        self.shared.state.store(state as u8, Ordering::Release);
    }
    /// 业务作用：在控制面实际副作用前取得本代写权，撤销与发布不能在两个检查之间交错。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍持有本代令牌时返回同步守卫；已退休返回空，调用方不得继续副作用。
    fn current_authority(&self) -> Option<MutexGuard<'_, Arc<()>>> {
        let active = self
            .shared
            .authority
            .lock()
            .expect("xDS authority lock poisoned");
        if !Arc::ptr_eq(&active, &self.owner) {
            // 配置相同或稍后回切也不复用旧令牌，迟到事件不能恢复先前权限。
            return None;
        }
        Some(active)
    }

    /// 业务作用：在后台重连或异步转换完成后识别退休代，减少无权任务继续消耗控制面资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：读取时仍持有本代权威为真；实际副作用仍须使用同步写入门。
    pub(super) fn is_current(&self) -> bool {
        self.current_authority().is_some()
    }

    /// 业务作用：把目录或完整配置发布与本代权威绑定，避免门外检查后被新代接管。
    ///
    /// 参数说明：
    /// - `action`：已完成异步准备、只含同步发布和提交的动作。
    ///
    /// 返回：仍获权时执行一次动作并交回结果；失权时无副作用返回空。
    pub(super) fn with_current<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let _authority = self.current_authority()?;
        Some(action())
    }

    /// 业务作用：把 ADS 订阅及确认入队绑定到任务代际，背压等待不延续旧任务权限。
    ///
    /// 参数说明：
    /// - `sender`：本代 ADS 流的有界发送队列。
    /// - `request`：已经校验的订阅、ACK 或 NACK。
    ///
    /// 返回：槽位可用且仍获权时入队；队列关闭或等待期间失权时不发送该消息。
    pub(super) async fn send_current<T>(
        &self,
        sender: &tokio::sync::mpsc::Sender<T>,
        request: T,
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        let permit = sender.reserve().await.context("ADS request queue closed")?;
        // reserve 可以跨过配置换代；取得槽位后在同步权威门内发送，旧代不能借空位重新取得写权。
        self.with_current(|| permit.send(request))
            .context("xDS generation authority changed before request queue")?;
        Ok(())
    }

    /// 业务作用：读取累计确认数量，用于判断当前重连轮次是否取得进展。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已确认响应累计数量，不授予任何发布权。
    pub(super) fn ack_total(&self) -> u64 {
        self.shared.ack_total.load(Ordering::Relaxed)
    }

    /// 业务作用：只由当前任务推进重连计数，退休任务结束不得污染新代生命周期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前代增加一次重连；失权时保持原计数。
    /// 失去本代权威时不改变当前状态。
    pub(super) fn mark_reconnect(&self) {
        let Some(_authority) = self.current_authority() else {
            // 失去控制权的任务不能继续记作当前来源的重连。
            return;
        };
        self.shared.reconnect_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录本代转换队列占用，旧 blocking 结果完成时不能清零新任务的占用。
    ///
    /// 参数说明：
    /// - `depth`：串行转换的当前占用，调用方只提供零或一。
    ///
    /// 返回：当前代更新队列深度；失权时无副作用。
    pub(super) fn set_apply_queue_depth(&self, depth: u64) {
        let Some(_authority) = self.current_authority() else {
            // 队列归属跟随任务代际，旧结束事件不代表新代已经完成。
            return;
        };
        self.shared
            .apply_queue_depth
            .store(depth, Ordering::Release);
    }
}
