//! xDS v3 ADS client 与 native 配置适配层。
//!
//! 外部 protobuf 只存在于控制面；SotW/Delta 资源通过全量校验后转换成 native endpoint、
//! cluster 与 route 计划，再走唯一发布链。数据面、路由和 LB 不直接依赖 Envoy API 类型。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use prost::Message;
use prost_types::{Any, Duration as ProtoDuration, Struct, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::client::Grpc;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint as TonicEndpoint, Identity,
};

use crate::config::model::XdsCfg;
use crate::config::model::{XdsResourceOwnerCfg, XdsTransportCfg};
use crate::config::GatewaySnapshot;
use crate::control::reload::ListenerTopologyReconciler;
use crate::control::reload::SnapshotApplyCoordinator;
#[cfg(feature = "xds-client-extensions")]
use crate::control::xds_resources::extensions::{
    translate_resources as translate_ecds_resources, ECDS_TYPE_URL,
};
use crate::control::xds_resources::{
    materialize_policy_snapshot, translate_cds_resources, translate_lds_resources,
    translate_rds_resources, translate_sds_resources, validate_cds_native, validate_rds_native,
    XdsClusterPlan, XdsLbPolicy, XdsListenerPlan, XdsPolicyCache, XdsPolicyOutcome,
    XdsPolicySnapshot, XdsResourceExhausted, XdsRouteTablePlan, XdsSecretPlan, XdsUpstreamProtocol,
    CDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL,
};
use crate::upstream::dynamic::{BindingIdentity, XdsPublisher};
use crate::upstream::{DynamicUpstreamStore, UpstreamInstance, XdsWatchSpec};

/// EDS v3 资源的规范 type URL。
pub const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
const ADS_SOTW_PATH: &str =
    "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";
const ADS_DELTA_PATH: &str =
    "/envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources";
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const INVALID_ARGUMENT_CODE: i32 = 3;
const RESOURCE_EXHAUSTED_CODE: i32 = 8;

/// xDS task 对 readiness/admin 暴露的低基数状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum XdsConnectionState {
    /// 尚未连通或首次同步失败。
    Disconnected = 0,
    /// ADS stream 已建立，等待第一份可接受 EDS。
    Syncing = 1,
    /// 最近 response 已完整应用并 ACK。
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
    /// 是否至少成功应用过一份 EDS。
    pub ready: bool,
    /// 当前 ADS HTTP/2 stream 是否仍连接。
    pub stream_up: bool,
    /// 当前数据面 LKG 对应的 opaque version。
    pub accepted_version: String,
    /// 各受支持 type 已 ACK 的独立 opaque version，键固定为 eds/cds/rds。
    pub accepted_versions: BTreeMap<String, String>,
    /// 最近 response nonce。
    pub last_nonce: String,
    /// 各受支持 type 最近 ACK/NACK nonce，键固定为 eds/cds/rds。
    pub last_nonces: BTreeMap<String, String>,
    /// 最近失败摘要，不含证书或资源原文。
    pub last_error: Option<String>,
    /// 当前 accepted 候选尚未闭合的低敏资源名，active 时为空。
    pub warming_dependencies: BTreeSet<String>,
    /// 当前已发布 native xDS 内容 SHA-256；不含秘密，也不作为认证凭据。
    pub applied_fingerprint: Option<String>,
    /// 已发送 ACK 数。
    pub ack_total: u64,
    /// 已发送 NACK 数。
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

/// ADS task 与 readiness/admin 之间的常驻状态句柄。
pub struct XdsStatus {
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
}

impl Default for XdsStatus {
    /// 业务作用：创建尚未取得任何 xDS 权威版本的 fail-closed 状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`Disconnected` 且 `ready=false` 的状态句柄。
    fn default() -> Self {
        Self {
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
        }
    }
}

impl XdsStatus {
    /// 业务作用：撤销上一 ADS 代的 readiness 与详情权威，防止新身份复用旧 ACK。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；累计计数保留，本代的 version/nonce/resource 从空状态重新取证。
    fn begin_generation(&self) {
        self.ready.store(false, Ordering::Release);
        self.stream_up.store(false, Ordering::Release);
        self.active_resources.store(0, Ordering::Release);
        self.apply_queue_depth.store(0, Ordering::Release);
        *self.detail.write().expect("xDS status lock poisoned") = XdsStatusDetail::default();
        self.state
            .store(XdsConnectionState::Disconnected as u8, Ordering::Release);
    }

    /// 业务作用：判断 require_xds 启动门是否已由一份完整 ACK 的 EDS 打开。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少成功应用过一次返回 true；断线后的 LKG 仍保持 true。
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// 业务作用：提供一致的 admin/metrics 低频快照，不暴露 protobuf 或秘密材料。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前状态、LKG version/nonce、错误摘要和累计 ACK/NACK/reconnect 计数。
    pub fn snapshot(&self) -> XdsStatusSnapshot {
        let detail = self.detail.read().expect("xDS status lock poisoned");
        XdsStatusSnapshot {
            state: XdsConnectionState::from_u8(self.state.load(Ordering::Acquire)),
            ready: self.ready(),
            stream_up: self.stream_up.load(Ordering::Acquire),
            accepted_version: detail.accepted_version.clone(),
            accepted_versions: detail.accepted_versions.clone(),
            last_nonce: detail.last_nonce.clone(),
            last_nonces: detail.last_nonces.clone(),
            last_error: detail.last_error.clone(),
            warming_dependencies: detail.warming_dependencies.clone(),
            applied_fingerprint: detail.applied_fingerprint.clone(),
            ack_total: self.ack_total.load(Ordering::Relaxed),
            nack_total: self.nack_total.load(Ordering::Relaxed),
            reconnect_total: self.reconnect_total.load(Ordering::Relaxed),
            duplicate_total: self.duplicate_total.load(Ordering::Relaxed),
            last_received_timestamp: self.last_received_timestamp.load(Ordering::Relaxed),
            last_applied_timestamp: self.last_applied_timestamp.load(Ordering::Relaxed),
            active_resources: self.active_resources.load(Ordering::Relaxed),
            active_resources_by_type: detail.active_resources_by_type.clone(),
            apply_queue_depth: self.apply_queue_depth.load(Ordering::Relaxed),
            rejected_bytes_total: self.rejected_bytes_total.load(Ordering::Relaxed),
            warming_timeout_total: self.warming_timeout_total.load(Ordering::Relaxed),
            ttl_expired_total: self.ttl_expired_total.load(Ordering::Relaxed),
        }
    }

    /// 业务作用：记录 stream 已建立但尚未取得首份可用配置的同步态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；已有 LKG 时保持 degraded 语义，不假装最新连接已经 active。
    fn mark_syncing(&self) {
        self.stream_up.store(true, Ordering::Release);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.state.store(next as u8, Ordering::Release);
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
    fn mark_accepted(
        &self,
        version: &str,
        nonce: &str,
        resource_count: usize,
        fingerprint: [u8; 32],
    ) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
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
        self.ack_total.fetch_add(1, Ordering::Relaxed);
        self.active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        self.state
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
    fn mark_rejected(&self, nonce: &str, error: &str, response_bytes: usize) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
            detail.last_nonce = nonce.to_owned();
            detail
                .last_nonces
                .insert("eds".to_owned(), nonce.to_owned());
            detail.last_error = Some(truncate_error(error));
        }
        self.nack_total.fetch_add(1, Ordering::Relaxed);
        self.rejected_bytes_total
            .fetch_add(response_bytes as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录 ADS 断线并保留已接受 LKG，防止控制面瞬断清空业务端点。
    ///
    /// 参数说明：
    /// - `error`：是连接或 stream 失败摘要。
    ///
    /// 返回：无；首份 EDS 前回到 disconnected，已有 LKG 后进入 degraded。
    fn mark_disconnected(&self, error: &str) {
        self.stream_up.store(false, Ordering::Release);
        self.detail
            .write()
            .expect("xDS status lock poisoned")
            .last_error = Some(truncate_error(error));
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Disconnected
        };
        self.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：读取当前 LKG version，供新 stream 初始 DiscoveryRequest 恢复 SotW 会话。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最近成功应用的 opaque version；尚无 LKG 时为空。
    fn accepted_version(&self) -> String {
        self.detail
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
    fn content_unchanged(&self, fingerprint: &[u8; 32]) -> bool {
        self.detail
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
    fn mark_duplicate(&self, version: &str, nonce: &str, resource_count: usize) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
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
        self.ack_total.fetch_add(1, Ordering::Relaxed);
        self.duplicate_total.fetch_add(1, Ordering::Relaxed);
        self.active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        self.state
            .store(XdsConnectionState::Active as u8, Ordering::Release);
    }

    /// 业务作用：登记已从 gRPC stream 收到一份完整 response，供故障时判断控制面新鲜度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；只更新低基数时间戳，不改变 accepted/applied 状态。
    fn mark_received(&self) {
        self.last_received_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
    }

    /// 业务作用：读取指定 resource type 的 accepted version，供重连恢复独立 SotW 会话。
    ///
    /// 参数说明：
    /// - `type_url`：是 EDS/CDS/RDS 规范 URL。
    ///
    /// 返回：该 type 最近 ACK version；尚未接受时为空。
    fn accepted_version_for(&self, type_url: &str) -> String {
        self.detail
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
    fn mark_policy_accepted(
        &self,
        type_url: &str,
        version: &str,
        nonce: &str,
        active_resources: Option<&BTreeMap<String, u64>>,
        applied_fingerprint: Option<&[u8; 32]>,
        missing: Option<&BTreeSet<String>>,
    ) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
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
        self.ack_total.fetch_add(1, Ordering::Relaxed);
        if let Some(active_resources) = active_resources {
            let total = active_resources.values().copied().sum::<u64>();
            self.detail
                .write()
                .expect("xDS status lock poisoned")
                .active_resources_by_type = active_resources.clone();
            self.active_resources.store(total, Ordering::Relaxed);
            self.last_applied_timestamp
                .store(unix_timestamp_seconds(), Ordering::Relaxed);
            self.ready.store(true, Ordering::Release);
            self.state
                .store(XdsConnectionState::Active as u8, Ordering::Release);
        } else {
            let state = if self.ready() {
                XdsConnectionState::Degraded
            } else {
                XdsConnectionState::Syncing
            };
            self.state.store(state as u8, Ordering::Release);
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
    fn mark_policy_rejected(
        &self,
        type_url: &str,
        nonce: &str,
        error: &str,
        response_bytes: usize,
    ) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
            detail.last_nonce = nonce.to_owned();
            detail
                .last_nonces
                .insert(xds_type_label(type_url).to_owned(), nonce.to_owned());
            detail.last_error = Some(truncate_error(error));
        }
        self.nack_total.fetch_add(1, Ordering::Relaxed);
        self.rejected_bytes_total
            .fetch_add(response_bytes as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录一轮合法但依赖长期不闭合的 warming 超时，不把它伪造成资源 NACK 或清空 LKG。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；首次同步保持 syncing，已有 LKG 保持 ready 并进入 degraded。
    fn mark_warming_timeout(&self) {
        self.detail
            .write()
            .expect("xDS status lock poisoned")
            .last_error =
            Some("xDS dependency warming deadline exceeded; retaining prior LKG".to_owned());
        self.warming_timeout_total.fetch_add(1, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：记录 Delta TTL 已在无控制面 response 时真实撤销并发布，保持 accepted version/nonce 不变。
    ///
    /// 参数说明：
    /// - `expired`：是本轮撤销资源数
    /// - `resource_count`：是发布后的 EDS 数
    /// - `fingerprint`：是发布后的 native 内容摘要。
    ///
    /// 返回：无；成功 publish 后保持/开放 ready；stream 在线为 active，断线期间保持 degraded。
    fn mark_eds_ttl_applied(&self, expired: usize, resource_count: usize, fingerprint: [u8; 32]) {
        let stream_up = self.stream_up.load(Ordering::Acquire);
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
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
        self.ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        self.active_resources
            .store(resource_count as u64, Ordering::Relaxed);
        self.last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        let state = if stream_up {
            XdsConnectionState::Active
        } else {
            XdsConnectionState::Degraded
        };
        self.state.store(state as u8, Ordering::Release);
    }

    /// 业务作用：记录 TTL 已撤销 accepted 候选但首次依赖仍不完整，不开放 readiness 或伪造 apply。
    ///
    /// 参数说明：
    /// - `expired`：是撤销数
    /// - `missing`：是撤销后仍未取得首次证据的资源名。
    ///
    /// 返回：无；保留旧 LKG（若有），状态为 syncing/degraded，并累计 TTL 撤销观测。
    fn mark_ttl_warming(&self, expired: usize, missing: &BTreeSet<String>) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
            detail.warming_dependencies = missing.clone();
            detail.last_error = Some(truncate_error(&format!(
                "xDS TTL expired while dependencies are warming: {}",
                missing.iter().cloned().collect::<Vec<_>>().join(",")
            )));
        }
        self.ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        let next = if self.ready() {
            XdsConnectionState::Degraded
        } else {
            XdsConnectionState::Syncing
        };
        self.state.store(next as u8, Ordering::Release);
    }

    /// 业务作用：ACK 只更新 per-resource version/TTL、native 内容未变化的 Delta response，避免无意义发布。
    ///
    /// 参数说明：
    /// - `type_url`：标识本轮控制消息；system version 仅用于诊断。
    /// - `system_version`：标识本轮控制消息；system version 仅用于诊断。
    /// - `nonce`：标识本轮控制消息；system version 仅用于诊断。
    ///
    /// 返回：无；推进该 type 的 ACK/nonce 与 duplicate 计数，保留当前 active/warming 状态和错误。
    fn mark_delta_duplicate(&self, type_url: &str, system_version: &str, nonce: &str) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
            let label = xds_type_label(type_url).to_owned();
            detail
                .accepted_versions
                .insert(label.clone(), system_version.to_owned());
            detail.last_nonces.insert(label, nonce.to_owned());
            detail.accepted_version = system_version.to_owned();
            detail.last_nonce = nonce.to_owned();
        }
        self.ack_total.fetch_add(1, Ordering::Relaxed);
        self.duplicate_total.fetch_add(1, Ordering::Relaxed);
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
    fn mark_policy_duplicate(
        &self,
        type_url: &str,
        system_version: &str,
        nonce: &str,
        resources: &BTreeMap<String, u64>,
        fingerprint: [u8; 32],
    ) {
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
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
        self.ack_total.fetch_add(1, Ordering::Relaxed);
        self.duplicate_total.fetch_add(1, Ordering::Relaxed);
        self.active_resources
            .store(resources.values().copied().sum(), Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        self.state
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
    fn mark_policy_ttl_applied(
        &self,
        expired: usize,
        resources: &BTreeMap<String, u64>,
        fingerprint: [u8; 32],
    ) {
        let stream_up = self.stream_up.load(Ordering::Acquire);
        {
            let mut detail = self.detail.write().expect("xDS status lock poisoned");
            if stream_up {
                detail.last_error = None;
            }
            detail.warming_dependencies.clear();
            detail.accepted_fingerprint = Some(fingerprint);
            detail.applied_fingerprint = Some(fingerprint_hex(&fingerprint));
            detail.active_resources_by_type = resources.clone();
        }
        self.ttl_expired_total
            .fetch_add(expired as u64, Ordering::Relaxed);
        self.active_resources
            .store(resources.values().copied().sum(), Ordering::Relaxed);
        self.last_applied_timestamp
            .store(unix_timestamp_seconds(), Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        let state = if stream_up {
            XdsConnectionState::Active
        } else {
            XdsConnectionState::Degraded
        };
        self.state.store(state as u8, Ordering::Release);
    }
}

/// xDS CDS/RDS apply 所需的唯一 Snapshot writer 依赖。
#[derive(Clone)]
pub struct XdsSnapshotRuntime {
    /// 当前数据面不可变快照。
    pub snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 与 file/Nacos 共用的成功版本序列。
    pub version: Arc<AtomicU64>,
    /// 与 reload worker 共用的发布写锁。
    pub apply_coordinator: Arc<SnapshotApplyCoordinator>,
    /// native Router/UpstreamDirectory 二次编译的路径基准。
    pub cfg_path: PathBuf,
    /// 与文件发布共用的事务及节点动作所有权门。
    pub config_history: crate::control::history::ConfigHistory,
    /// LDS owner 的 listener 两阶段事务；native-listener profile 为 None。
    pub listener_topology: Option<Arc<dyn ListenerTopologyReconciler>>,
}

/// xDS ADS 任务的进程级 owner，使 bootstrap/ownership 变更可以经过预连接后换代。
pub struct XdsGenerationManager {
    dynamic: Arc<DynamicUpstreamStore>,
    snapshot_runtime: XdsSnapshotRuntime,
    status: Arc<XdsStatus>,
    active: parking_lot::Mutex<Option<JoinHandle<()>>>,
}

/// 已完成 management server 传输与身份复验的 xDS 候选代。
pub struct PreparedXdsGeneration {
    manager: Arc<XdsGenerationManager>,
    cfg: Option<XdsCfg>,
    specs: Vec<XdsWatchSpec>,
}

impl XdsGenerationManager {
    /// 业务作用：创建 xDS 单 owner 管理器，使所有代共用快照写锁、状态与动态实例表。
    ///
    /// 参数说明：
    /// - `dynamic`：是 EDS 事实源
    /// - `snapshot_runtime`：是 CDS/RDS/LDS 唯一发布边界
    /// - `status`：是 admin/readiness 持有的稳定状态句柄。
    ///
    /// 返回：返回尚未启动 ADS 任务的管理器。
    pub fn new(
        dynamic: Arc<DynamicUpstreamStore>,
        snapshot_runtime: XdsSnapshotRuntime,
        status: Arc<XdsStatus>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dynamic,
            snapshot_runtime,
            status,
            active: parking_lot::Mutex::new(None),
        })
    }

    /// 业务作用：启动初始 ADS 代，只在 listener supervisor 已建立后调用。
    ///
    /// 参数说明：
    /// - `cfg`：是启动期 xDS 计划
    /// - `specs`：是 EDS 服务映射。
    ///
    /// 返回：无返回值；网络故障由后台退避并反映为未就绪。
    pub fn start_initial(&self, cfg: XdsCfg, specs: Vec<XdsWatchSpec>) {
        self.status.begin_generation();
        let task = spawn_inner_with_status(
            cfg,
            specs,
            self.dynamic.clone(),
            Some(self.snapshot_runtime.clone()),
            self.status.clone(),
        );
        *self.active.lock() = Some(task);
    }

    /// 业务作用：在不触碰当前 ADS owner 的前提下，复验候选 server、TLS/mTLS 身份与连接 deadline。
    ///
    /// 参数说明：
    /// - `cfg`：为 None 表示候选关闭 xDS
    /// - `specs`：是候选 EDS owner 映射。
    ///
    /// 返回：传输与身份成功时返回可提交代；解析、建连、TLS 或 deadline 失败保留旧代。
    pub async fn prepare(
        self: &Arc<Self>,
        cfg: Option<XdsCfg>,
        specs: Vec<XdsWatchSpec>,
    ) -> Result<PreparedXdsGeneration> {
        if let Some(cfg) = &cfg {
            // 预连接会完整执行 DNS/TCP/TLS/mTLS，但不发送 DiscoveryRequest，
            // 因此候选在发布前不可写 EDS 或 Snapshot owner 域。
            let _channel = connect_channel(cfg).await?;
        }
        Ok(PreparedXdsGeneration {
            manager: self.clone(),
            cfg,
            specs,
        })
    }
}

impl PreparedXdsGeneration {
    /// 业务作用：在候选快照已发布后撤销旧 ADS owner，并启动候选代。
    ///
    /// 参数说明: 无。
    ///
    /// 事务已持有候选计划和唯一管理器。
    ///
    /// 返回：无返回值；旧 task 先失去后续写权，新 task 才使用同一发布锁。
    pub fn commit(self) {
        if self.cfg.is_none() {
            // 关闭来源先撤销目录发布权，单独 abort 无法约束另一线程已进入的同步发布分支。
            self.manager.dynamic.revoke_xds();
        }
        if let Some(old) = self.manager.active.lock().take() {
            old.abort();
        }
        self.manager.status.begin_generation();
        if let Some(cfg) = self.cfg {
            let task = spawn_inner_with_status(
                cfg,
                self.specs,
                self.manager.dynamic.clone(),
                Some(self.manager.snapshot_runtime.clone()),
                self.manager.status.clone(),
            );
            *self.manager.active.lock() = Some(task);
        }
    }
}

/// 启动单一 ADS task。
///
/// 业务作用：为所有 `source: xds` 服务建立共享有界 stream，并把 EDS response 通过统一
/// native adapter 发布到动态目录；每个进程只应调用一次。
///
/// 参数说明：
/// - `cfg`：是已完成 bootstrap 校验的 xDS 配置
/// - `specs`：固定 cluster/service 映射
/// - `dynamic`：是与数据面快照共享的动态实例表。
///
/// 返回：立即返回状态句柄；网络连接与重试在后台 task 中运行。
pub fn spawn(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    dynamic: Arc<DynamicUpstreamStore>,
) -> Arc<XdsStatus> {
    spawn_inner(cfg, specs, dynamic, None)
}

/// 业务作用：启动可同时拥有 CDS/RDS/EDS 的 ADS task，并把完整依赖闭包交给共享 single-writer。
///
/// 参数说明：
/// - `cfg`：已校验的 xDS bootstrap 配置。
/// - `specs`：EDS-only 模式的受管服务声明。
/// - `dynamic`：共享动态实例目录。
/// - `snapshot_runtime`：当前快照、版本与统一发布锁组成的快照发布权威。
///
/// 返回：立即返回状态句柄；后台只在 CDS/RDS/EDS 全闭合且 native 二次编译成功后发布。
pub fn spawn_with_snapshot(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    dynamic: Arc<DynamicUpstreamStore>,
    snapshot_runtime: XdsSnapshotRuntime,
) -> Arc<XdsStatus> {
    spawn_inner(cfg, specs, dynamic, Some(snapshot_runtime))
}

/// 业务作用：在 listener supervisor 就绪前创建 fail-closed xDS 状态，供 admin/readiness 提前接线。
///
/// 参数说明: 无。
///
/// 返回：尚未启动网络 task、`ready=false` 的共享状态句柄。
pub fn new_status() -> Arc<XdsStatus> {
    Arc::new(XdsStatus::default())
}

/// 业务作用：使用预先暴露给 admin 的状态句柄启动 ADS，确保 LDS task 不早于 listener supervisor。
///
/// 参数说明：
/// - `cfg`：与 [`spawn_with_snapshot`] 相同
/// - `specs`：与 [`spawn_with_snapshot`] 相同
/// - `dynamic`：与 [`spawn_with_snapshot`] 相同
/// - `snapshot_runtime`：与 [`spawn_with_snapshot`] 相同
/// - `status`：是 启动前已接入 readiness 的唯一句柄。
///
/// 返回：无；后台 task 生命周期覆盖进程，所有状态写入调用方提供的同一句柄。
pub fn start_with_snapshot_status(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    dynamic: Arc<DynamicUpstreamStore>,
    snapshot_runtime: XdsSnapshotRuntime,
    status: Arc<XdsStatus>,
) {
    drop(spawn_inner_with_status(
        cfg,
        specs,
        dynamic,
        Some(snapshot_runtime),
        status,
    ));
}

/// 业务作用：统一创建 EDS-only 或 CDS/RDS/EDS profile 的常驻状态与后台任务。
///
/// 参数说明：
/// - `cfg`：已校验的 xDS bootstrap 配置。
/// - `specs`：EDS-only 模式的受管服务声明。
/// - `dynamic`：共享动态实例目录。
/// - `snapshot_runtime`：routes 或 clusters 由 xDS 持有时必需的快照发布权威。
///
/// 返回：共享状态句柄；task 的错误由内部重连循环吸收并反映为 degraded/disconnected。
fn spawn_inner(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    dynamic: Arc<DynamicUpstreamStore>,
    snapshot_runtime: Option<XdsSnapshotRuntime>,
) -> Arc<XdsStatus> {
    let status = Arc::new(XdsStatus::default());
    drop(spawn_inner_with_status(
        cfg,
        specs,
        dynamic,
        snapshot_runtime,
        status.clone(),
    ));
    status
}

/// 业务作用：把已创建状态与 EDS-only/完整 policy ADS 后台循环绑定，保证进程只有一个状态权威。
///
/// 参数说明：
/// - `cfg`：已校验的 xDS bootstrap 配置。
/// - `specs`：EDS-only 模式的受管服务声明。
/// - `dynamic`：共享动态实例目录。
/// - `snapshot_runtime`：routes 或 clusters 由 xDS 持有时使用的快照发布权威。
/// - `status`：可由管理面提前持有的控制器状态。
///
/// 返回：返回 task 句柄，换代 owner 可以撤销旧 stream 及其迟到写入。
fn spawn_inner_with_status(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    dynamic: Arc<DynamicUpstreamStore>,
    snapshot_runtime: Option<XdsSnapshotRuntime>,
    status: Arc<XdsStatus>,
) -> JoinHandle<()> {
    // 先同步领取整批写权，再启动网络任务；旧 stream 的迟到响应不能通过目录发布门。
    let publisher = dynamic.claim_xds(
        specs
            .iter()
            .map(|spec| (spec.logical_service.clone(), BindingIdentity::xds(spec)))
            .collect(),
    );
    tokio::spawn(async move {
        run_forever(cfg, specs, publisher, snapshot_runtime, status).await;
    })
}

/// 业务作用：永久维护 ADS 连接，以带 jitter 的指数退避抵抗 management server 故障风暴。
///
/// 参数说明：
/// - `cfg`：已校验的 xDS bootstrap 配置。
/// - `specs`：EDS-only 模式的受管服务声明。
/// - `publisher`：本代 EDS 批次的同步发布权。
/// - `snapshot_runtime`：routes 或 clusters 由 xDS 持有时使用的快照发布权威。
/// - `status`：管理面可观察的控制器状态。
///
/// 返回：正常运行不返回；仅进程 runtime 取消 task 时结束。
async fn run_forever(
    cfg: XdsCfg,
    specs: Vec<XdsWatchSpec>,
    publisher: XdsPublisher,
    snapshot_runtime: Option<XdsSnapshotRuntime>,
    status: Arc<XdsStatus>,
) {
    let initial_backoff = parse_duration(&cfg.reconnect.initial_backoff)
        .unwrap_or_else(|| Duration::from_millis(200));
    let max_backoff =
        parse_duration(&cfg.reconnect.max_backoff).unwrap_or_else(|| Duration::from_secs(30));
    let mut backoff = initial_backoff;
    let policy_owned = cfg.ownership.routes == XdsResourceOwnerCfg::Xds;
    let mut policy = if policy_owned {
        let runtime = snapshot_runtime
            .as_ref()
            .expect("validated xDS policy profile requires snapshot runtime");
        Some(XdsPolicySession::new(runtime.snap.load().as_ref()))
    } else {
        None
    };
    let mut delta_eds = DeltaResourceCache::default();
    while publisher.is_current() {
        let acknowledgements_before = status.ack_total.load(Ordering::Relaxed);
        let stream_result =
            if let (Some(policy), Some(runtime)) = (policy.as_mut(), snapshot_runtime.as_ref()) {
                if cfg.transport == XdsTransportCfg::AdsDeltaV3 {
                    run_delta_policy_stream(&cfg, policy, runtime, status.clone()).await
                } else {
                    run_policy_stream(&cfg, policy, runtime, status.clone()).await
                }
            } else if cfg.transport == XdsTransportCfg::AdsDeltaV3 {
                run_delta_stream(
                    &cfg,
                    &specs,
                    &mut delta_eds,
                    publisher.clone(),
                    status.clone(),
                )
                .await
            } else {
                run_stream(&cfg, &specs, publisher.clone(), status.clone()).await
            };
        if !publisher.is_current() {
            // 新代已接管目录，旧连接结束不能重置当前共享连接状态或继续重连。
            return;
        }
        match stream_result {
            Ok(()) => status.mark_disconnected("ADS stream ended without status"),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "xDS ADS stream disconnected");
                status.mark_disconnected(&format!("{error:#}"));
            }
        }
        status.reconnect_total.fetch_add(1, Ordering::Relaxed);
        let accepted_this_stream =
            status.ack_total.load(Ordering::Relaxed) > acknowledgements_before;
        let sleep_backoff = if accepted_this_stream {
            initial_backoff
        } else {
            backoff
        };
        wait_reconnect_delay(
            &cfg,
            jittered(sleep_backoff, cfg.reconnect.jitter),
            &specs,
            &mut delta_eds,
            &publisher,
            policy.as_mut(),
            snapshot_runtime.as_ref(),
            status.as_ref(),
        )
        .await;
        backoff = if accepted_this_stream {
            // 本代 stream 已真正应用过 response，说明管理面曾恢复；下一次独立故障应从
            // 初始退避重新计时，不能让历史失败把后续恢复拖到旧的最大窗口。
            initial_backoff
        } else {
            backoff.saturating_mul(2).min(max_backoff)
        };
    }
}

/// 业务作用：重连退避期间继续执行 Delta TTL/warming timer，管理面断线不能把资源寿命延长到下一条 stream。
///
/// 参数说明：
/// - `cfg`：固定的 xDS bootstrap 配置。
/// - `delay`：本次 jitter 后的重连等待时长。
/// - `specs`：EDS-only 模式的受管服务声明。
/// - `delta_eds`：Delta EDS 已接收资源缓存。
/// - `publisher`：本代 EDS 批次的同步发布权。
/// - `policy`：受管策略资源缓存。
/// - `runtime`：快照发布权威与常驻运行态。
/// - `status`：管理面可观察的控制器状态。
///
/// 返回：退避到期后返回；timer apply 失败时保留旧数据面并提前返回，让下一次连接尽快重新取证。
#[allow(clippy::too_many_arguments)]
async fn wait_reconnect_delay(
    cfg: &XdsCfg,
    delay: Duration,
    specs: &[XdsWatchSpec],
    delta_eds: &mut DeltaResourceCache,
    publisher: &XdsPublisher,
    mut policy: Option<&mut XdsPolicySession>,
    runtime: Option<&XdsSnapshotRuntime>,
    status: &XdsStatus,
) {
    if cfg.transport != XdsTransportCfg::AdsDeltaV3 {
        tokio::time::sleep(delay).await;
        return;
    }
    let reconnect_deadline = Instant::now() + delay;
    let warming_timeout =
        parse_duration(&cfg.limits.warming_timeout).unwrap_or_else(|| Duration::from_secs(60));
    loop {
        let timer_deadline = if let Some(policy) = policy.as_deref() {
            delta_policy_deadline(policy, warming_timeout)
        } else {
            delta_eds.next_expiry()
        };
        let Some(timer_deadline) =
            timer_deadline.filter(|deadline| *deadline <= reconnect_deadline)
        else {
            tokio::time::sleep_until(tokio::time::Instant::from_std(reconnect_deadline)).await;
            return;
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(timer_deadline)).await;
        let applied = if let Some(policy) = policy.as_deref_mut() {
            apply_delta_policy_timers(
                policy,
                runtime.expect("validated policy profile has Snapshot runtime"),
                status,
                &cfg.limits,
                warming_timeout,
            )
            .await
            .map(|_| ())
        } else {
            apply_delta_eds_expiry(delta_eds, specs, publisher, status, &cfg.limits).await
        };
        if let Err(error) = applied {
            // timer 变更也必须先完整翻译再发布；失败时保留 cache/Snapshot，立即重连获取新证据，
            // 不能继续在本地重复执行同一失败 deadline 形成空转。
            tracing::warn!(error = %format!("{error:#}"), "xDS Delta timer apply failed during reconnect backoff");
            return;
        }
    }
}

/// Delta xDS 单 type 的已接受资源、opaque version 与 TTL deadline。
#[derive(Clone, Default)]
struct DeltaResourceCache {
    resources: BTreeMap<String, Any>,
    versions: BTreeMap<String, String>,
    observed: BTreeSet<String>,
    expiries: BTreeMap<String, Instant>,
}

impl DeltaResourceCache {
    /// 业务作用：事务性合并一份 Delta response，确保坏 wrapper、heartbeat 或 remove 不污染 LKG cache。
    ///
    /// 参数说明：
    /// - `response`：是一个 type 的增量
    /// - `expected_type`：是本地订阅域
    /// - `limits`：是硬预算
    /// - `now`：为全部 TTL 使用同一单调时钟锚点。
    ///
    /// 返回：成功时返回完整下一 cache 与 payload 是否变化；失败时原 cache 保持不变。
    fn apply_response(
        &self,
        response: &DeltaDiscoveryResponse,
        expected_type: &str,
        limits: &crate::config::model::XdsLimitsCfg,
        now: Instant,
    ) -> Result<(Self, bool)> {
        validate_delta_response_envelope(response, expected_type, limits)?;
        let mut next = self.clone();
        let mut changed = false;
        let mut removed_names = BTreeSet::new();
        for removed in &response.removed_resources {
            validate_delta_resource_name(removed, "Delta removed resource")?;
            anyhow::ensure!(
                removed_names.insert(removed.clone()),
                "duplicate Delta removed resource name"
            );
        }
        let mut updated_names = BTreeSet::new();
        for resource in &response.resources {
            validate_delta_resource(resource, &response.type_url, limits)?;
            anyhow::ensure!(
                updated_names.insert(resource.name.clone()),
                "duplicate Delta resource name"
            );
            anyhow::ensure!(
                !removed_names.contains(&resource.name),
                "Delta response cannot update and remove the same resource"
            );
            let ttl = resource.ttl.as_ref().map(delta_ttl).transpose()?;
            match &resource.resource {
                Some(payload) => {
                    let same_payload = next.resources.get(&resource.name).is_some_and(|current| {
                        current.type_url == payload.type_url && current.value == payload.value
                    });
                    changed |= !same_payload;
                    next.resources
                        .insert(resource.name.clone(), payload.clone());
                    next.versions
                        .insert(resource.name.clone(), resource.version.clone());
                    if expected_type == EDS_TYPE_URL {
                        changed |= next.observed.insert(resource.name.clone());
                    }
                    if let Some(ttl) = ttl {
                        next.expiries.insert(resource.name.clone(), now + ttl);
                    } else {
                        next.expiries.remove(&resource.name);
                    }
                }
                None => {
                    anyhow::ensure!(
                        ttl.is_some(),
                        "Delta heartbeat requires ttl and an omitted resource payload"
                    );
                    anyhow::ensure!(
                        next.resources.contains_key(&resource.name)
                            && next.versions.get(&resource.name) == Some(&resource.version),
                        "Delta heartbeat requires the currently accepted resource version"
                    );
                    next.expiries
                        .insert(resource.name.clone(), now + ttl.expect("checked ttl"));
                }
            }
        }
        for removed in removed_names {
            changed |= next.resources.remove(&removed).is_some();
            next.versions.remove(&removed);
            next.expiries.remove(&removed);
            if expected_type == EDS_TYPE_URL {
                changed |= next.observed.insert(removed);
            }
        }
        if next.resources.len() > limits.max_warming_resources {
            return Err(
                XdsResourceExhausted("Delta accepted cache exceeds max_warming_resources").into(),
            );
        }
        if next.observed.len() > limits.max_warming_resources {
            return Err(
                XdsResourceExhausted("Delta observed cache exceeds max_warming_resources").into(),
            );
        }
        let resource_bytes =
            next.resources
                .iter()
                .try_fold(0usize, |total, (name, payload)| -> Result<usize> {
                    total
                        .checked_add(name.len())
                        .and_then(|value| {
                            value.checked_add(next.versions.get(name).map_or(0, String::len))
                        })
                        .and_then(|value| value.checked_add(payload.encoded_len()))
                        .context("Delta accepted cache byte accounting overflow")
                })?;
        let retained_bytes = next
            .observed
            .iter()
            .filter(|name| !next.resources.contains_key(*name))
            .try_fold(resource_bytes, |total, name| {
                total
                    .checked_add(name.len())
                    .context("Delta observed cache byte accounting overflow")
            })?;
        if retained_bytes > limits.max_response_bytes {
            return Err(
                XdsResourceExhausted("Delta accepted cache exceeds max_response_bytes").into(),
            );
        }
        Ok((next, changed))
    }

    /// 业务作用：生成重连首请求的 per-resource opaque version，避免服务器重发已缓存的大资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅包含当前仍持有 payload 的资源；removed/TTL-expired 项不会伪报版本。
    fn initial_versions(&self) -> HashMap<String, String> {
        self.versions
            .iter()
            .map(|(name, version)| (name.clone(), version.clone()))
            .collect()
    }

    /// 业务作用：取得当前完整 payload 集，供既有 SotW translator 复用同一字段和 native 校验器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按 resource name 稳定排序的 Any clone；控制面低频路径允许复制引用外壳与 bytes。
    fn resource_values(&self) -> Vec<Any> {
        self.resources.values().cloned().collect()
    }

    /// 业务作用：CDS 派生订阅变化时清除已失去 transport identity 的 EDS payload/version/TTL 证据。
    ///
    /// 参数说明：
    /// - `retain`：是仍由同一 logical service/protocol/timeout 使用的 physical resource 名。
    ///
    /// 返回：无；被清除资源不会进入重连 initial versions，必须由 server 重新发送。
    fn retain_resources(&mut self, retain: &BTreeSet<String>) {
        self.resources.retain(|name, _| retain.contains(name));
        self.versions.retain(|name, _| retain.contains(name));
        self.observed.retain(|name| retain.contains(name));
        self.expiries.retain(|name, _| retain.contains(name));
    }

    /// 业务作用：为 receive loop 提供本 type 最早 TTL deadline，确保控制面静默时资源仍准时撤销。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少一项带 TTL 时返回最早单调时钟点，否则返回 None。
    fn next_expiry(&self) -> Option<Instant> {
        self.expiries.values().copied().min()
    }

    /// 业务作用：删除所有已到期 payload 和 version，把 TTL 语义落实为资源 removal 而非回退旧版。
    ///
    /// 参数说明：
    /// - `now`：是本轮统一单调时钟
    /// - `mark_observed`：仅供 named EDS 保留显式删除证据。
    ///
    /// 返回：实际删除 payload 的 resource 名；仅清理陈旧 timer 不计为数据变化。
    fn expire_due(&mut self, now: Instant, mark_observed: bool) -> BTreeSet<String> {
        let expired = self
            .expiries
            .iter()
            .filter_map(|(name, deadline)| (*deadline <= now).then_some(name.clone()))
            .collect::<BTreeSet<_>>();
        let mut removed = BTreeSet::new();
        for name in expired {
            self.expiries.remove(&name);
            self.versions.remove(&name);
            if self.resources.remove(&name).is_some() {
                removed.insert(name.clone());
            }
            if mark_observed {
                self.observed.insert(name);
            }
        }
        removed
    }
}

/// 业务作用：校验 Delta response 控制字段与总资源预算，拒绝已知但未支持的 variant/error surface。
///
/// 参数说明：
/// - `response`：是 tonic 解码结果
/// - `expected_type`：是当前订阅
/// - `limits`：是 bootstrap 硬门。
///
/// 返回：当前选择性 Delta surface 合法时成功；类型、nonce、扩展或预算异常时失败。
fn validate_delta_response_envelope(
    response: &DeltaDiscoveryResponse,
    expected_type: &str,
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<()> {
    anyhow::ensure!(
        response.type_url == expected_type,
        "unexpected Delta ADS type_url"
    );
    anyhow::ensure!(
        response.system_version_info.len() <= 256,
        "Delta system_version_info exceeds 256 bytes"
    );
    anyhow::ensure!(
        !response.nonce.is_empty() && response.nonce.len() <= 256,
        "Delta nonce must be 1..=256 bytes"
    );
    anyhow::ensure!(
        response.control_plane.is_none()
            && response.removed_resource_names.is_empty()
            && response.resource_errors.is_empty(),
        "unsupported Delta ADS control-plane/resource-name/error extension"
    );
    if response.encoded_len() > limits.max_response_bytes {
        return Err(XdsResourceExhausted("Delta response exceeds max_response_bytes").into());
    }
    if response
        .resources
        .len()
        .saturating_add(response.removed_resources.len())
        > limits.max_resources_per_type
    {
        return Err(XdsResourceExhausted("Delta changes exceed max_resources_per_type").into());
    }
    Ok(())
}

/// 业务作用：校验单个 Delta Resource wrapper、opaque version、TTL 和当前允许的 name/Any surface。
///
/// 参数说明：
/// - `resource`：是 wrapper
/// - `expected_type`：是内层 Any type
/// - `limits`：约束 payload bytes。
///
/// 返回：常规 upsert 或合法 heartbeat 成功；alias/variant/cache/metadata 与坏 TTL 失败。
fn validate_delta_resource(
    resource: &DeltaResource,
    expected_type: &str,
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<()> {
    validate_delta_resource_name(&resource.name, "Delta Resource.name")?;
    anyhow::ensure!(
        !resource.version.is_empty() && resource.version.len() <= 256,
        "Delta Resource.version must be 1..=256 bytes"
    );
    anyhow::ensure!(
        resource.aliases.is_empty()
            && resource.cache_control.is_none()
            && resource.resource_name.is_none()
            && resource.metadata.is_none(),
        "unsupported Delta Resource alias/variant/cache/metadata"
    );
    if let Some(payload) = &resource.resource {
        anyhow::ensure!(
            payload.type_url == expected_type,
            "Delta Resource Any has mismatched type_url"
        );
        if payload.value.len() > limits.max_resource_bytes {
            return Err(XdsResourceExhausted("Delta resource exceeds max_resource_bytes").into());
        }
    }
    Ok(())
}

/// 业务作用：限制 Delta wrapper/removal 名称到可安全进入 cache key、诊断与订阅的稳定 ASCII。
///
/// 参数说明：
/// - `value`：是资源名
/// - `field`：只用于低敏错误定位。
///
/// 返回：1..=256 safe ASCII 成功；空值、控制字符和高风险分隔符失败。
fn validate_delta_resource_name(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
            }),
        "{field} is outside the safe resource-name allowlist"
    );
    Ok(())
}

/// 业务作用：把 Resource.ttl 转成有界单调时钟 duration，防止负值、非规范 nanos 或超长 timer。
///
/// 参数说明：
/// - `ttl`：是 Envoy v3 protobuf duration。
///
/// 返回：1ms..=24h 时成功；更细精度、零值、负值和溢出失败。
fn delta_ttl(ttl: &ProtoDuration) -> Result<Duration> {
    anyhow::ensure!(
        ttl.seconds >= 0 && (0..1_000_000_000).contains(&ttl.nanos),
        "Delta Resource.ttl is not a canonical positive duration"
    );
    let seconds = u64::try_from(ttl.seconds).context("Delta Resource.ttl seconds overflow")?;
    let nanos = u32::try_from(ttl.nanos).context("Delta Resource.ttl nanos overflow")?;
    let duration = Duration::new(seconds, nanos);
    anyhow::ensure!(
        duration >= Duration::from_millis(1) && duration <= Duration::from_secs(24 * 60 * 60),
        "Delta Resource.ttl must be within 1ms..=24h"
    );
    Ok(duration)
}

/// ADS 多 type 会话的 accepted cache 与尚未发布 EDS 候选。
#[derive(Clone)]
struct XdsPolicySession {
    cache: XdsPolicyCache,
    endpoints: HashMap<String, Vec<UpstreamInstance>>,
    /// 保护发布必须复用已发布的实例表，不得混入仍在 warming 的 EDS 候选。
    active_endpoints: HashMap<String, Vec<UpstreamInstance>>,
    specs: Vec<XdsWatchSpec>,
    route_names: BTreeSet<String>,
    secret_names: BTreeSet<String>,
    listener_owned: bool,
    secret_owned: bool,
    delta_lds: DeltaResourceCache,
    delta_cds: DeltaResourceCache,
    delta_rds: DeltaResourceCache,
    delta_eds: DeltaResourceCache,
    delta_sds: DeltaResourceCache,
    #[cfg(feature = "xds-client-extensions")]
    extension_names: BTreeSet<String>,
    #[cfg(feature = "xds-client-extensions")]
    delta_ecds: DeltaResourceCache,
}

impl XdsPolicySession {
    /// 业务作用：从 native listener ids 建立 fail-closed 的 RDS 命名订阅与空依赖闭包。
    ///
    /// 参数说明：
    /// - `snapshot`：是进程启动时已校验的 bootstrap 快照。
    ///
    /// 返回：没有 active policy/endpoint，必须等待 CDS/RDS/EDS 三域闭合的会话。
    fn new(snapshot: &GatewaySnapshot) -> Self {
        let listener_owned =
            snapshot.control_plane.xds.ownership.listeners == XdsResourceOwnerCfg::Xds;
        let secret_owned = snapshot.control_plane.xds.ownership.secrets == XdsResourceOwnerCfg::Xds;
        let route_names = snapshot
            .proxies
            .iter()
            .map(|proxy| proxy.id.clone())
            .collect::<BTreeSet<_>>();
        Self {
            cache: if listener_owned {
                XdsPolicyCache::new_full_xds()
            } else {
                XdsPolicyCache::new(route_names.clone())
            },
            endpoints: HashMap::new(),
            active_endpoints: HashMap::new(),
            specs: Vec::new(),
            route_names,
            secret_names: BTreeSet::new(),
            listener_owned,
            secret_owned,
            delta_lds: DeltaResourceCache::default(),
            delta_cds: DeltaResourceCache::default(),
            delta_rds: DeltaResourceCache::default(),
            delta_eds: DeltaResourceCache::default(),
            delta_sds: DeltaResourceCache::default(),
            #[cfg(feature = "xds-client-extensions")]
            extension_names: BTreeSet::new(),
            #[cfg(feature = "xds-client-extensions")]
            delta_ecds: DeltaResourceCache::default(),
        }
    }

    /// 业务作用：LDS accepted 后原子更新 RDS/SDS/ECDS 命名订阅，并清除失去归属的 Delta cache。
    ///
    /// 参数说明：
    /// - `listeners`：是整份已验证 LDS 候选。
    ///
    /// 返回：RDS、SDS、ECDS 订阅是否分别变化；调用方据此发送 subscribe/unsubscribe。
    fn refresh_listener_dependencies(
        &mut self,
        listeners: &BTreeMap<String, XdsListenerPlan>,
    ) -> (bool, bool, bool) {
        let routes = listeners
            .values()
            .map(|listener| listener.route_name.clone())
            .collect::<BTreeSet<_>>();
        let secrets = listeners
            .values()
            .filter_map(|listener| listener.tls.as_ref())
            .flat_map(|tls| {
                std::iter::once(tls.certificate_secret.clone()).chain(tls.validation_secret.clone())
            })
            .collect::<BTreeSet<_>>();
        let routes_changed = routes != self.route_names;
        let secrets_changed = secrets != self.secret_names;
        if routes_changed {
            self.delta_rds.retain_resources(&routes);
            self.route_names = routes;
        }
        if secrets_changed {
            self.delta_sds.retain_resources(&secrets);
            self.secret_names = secrets;
        }
        #[cfg(feature = "xds-client-extensions")]
        let extensions_changed = {
            let names = listeners
                .values()
                .filter_map(|listener| listener.extension_name.clone())
                .collect::<BTreeSet<_>>();
            let changed = names != self.extension_names;
            self.delta_ecds.retain_resources(&names);
            self.extension_names = names;
            changed
        };
        #[cfg(not(feature = "xds-client-extensions"))]
        let extensions_changed = false;
        (routes_changed, secrets_changed, extensions_changed)
    }

    /// 业务作用：从 accepted CDS 派生唯一 EDS cluster→native service 订阅，禁止另一份本地映射介入。
    ///
    /// 参数说明：
    /// - `clusters`：是本轮已完成字段白名单校验、尚未写入 cache 的 CDS 全集。
    ///
    /// 返回：订阅内容相对上一代发生变化时返回 true，调用方必须发送新的 EDS DiscoveryRequest。
    fn refresh_eds_specs(&mut self, clusters: &BTreeMap<String, XdsClusterPlan>) -> bool {
        let mut next = clusters
            .values()
            .map(|cluster| XdsWatchSpec {
                logical_service: cluster.name.clone(),
                cluster_name: cluster.eds_service_name.clone(),
                protocol: match cluster.protocol {
                    XdsUpstreamProtocol::H1 => crate::upstream::UpstreamProtocol::H1,
                    XdsUpstreamProtocol::H2c => crate::upstream::UpstreamProtocol::H2c,
                },
                connect_timeout_ms: cluster.connect_timeout_ms,
                scheme: "http".to_owned(),
                slow_start_ms: 0,
                tls_profile: None,
            })
            .collect::<Vec<_>>();
        next.sort_by(|left, right| {
            left.cluster_name
                .cmp(&right.cluster_name)
                .then_with(|| left.logical_service.cmp(&right.logical_service))
        });
        if next == self.specs {
            return false;
        }
        let reusable = next
            .iter()
            .filter(|candidate| self.specs.iter().any(|current| current == *candidate))
            .map(|spec| spec.cluster_name.clone())
            .collect::<BTreeSet<_>>();
        let reusable_services = next
            .iter()
            .filter(|candidate| self.specs.iter().any(|current| current == *candidate))
            .map(|spec| spec.logical_service.clone())
            .collect::<BTreeSet<_>>();
        // EDS payload 本身不携带 CDS transport；protocol/connect timeout 变化后，旧 native
        // UpstreamInstance 不能直接复用，否则 ACK 的新 CDS 会继续以旧 connector 身份拨号。
        self.cache.retain_endpoint_clusters(&reusable);
        self.delta_eds.retain_resources(&reusable);
        self.endpoints
            .retain(|service, _| reusable_services.contains(service));
        self.specs = next;
        true
    }

    /// 业务作用：返回指定 resource type 当前完整订阅名，ACK/NACK 也必须重复它以免变成 wildcard。
    ///
    /// 参数说明：
    /// - `type_url`：是 CDS/RDS/EDS 规范 URL。
    ///
    /// 返回：CDS 为空表示明确 wildcard；RDS/EDS 返回稳定排序的 owner 名集合。
    fn resource_names(&self, type_url: &str) -> Result<Vec<String>> {
        match type_url {
            LDS_TYPE_URL => Ok(Vec::new()),
            CDS_TYPE_URL => Ok(Vec::new()),
            RDS_TYPE_URL => Ok(self.route_names.iter().cloned().collect()),
            EDS_TYPE_URL => subscribed_clusters(&self.specs),
            SDS_TYPE_URL => Ok(self.secret_names.iter().cloned().collect()),
            #[cfg(feature = "xds-client-extensions")]
            ECDS_TYPE_URL => Ok(if self.extension_names.is_empty() {
                vec!["!naway-unsubscribed".to_owned()]
            } else {
                self.extension_names.iter().cloned().collect()
            }),
            other => bail!("unsupported ADS resource type `{other}`"),
        }
    }
}

enum XdsPolicyTranslation {
    #[cfg(feature = "xds-client-extensions")]
    Ecds(BTreeSet<String>),
    Lds(BTreeMap<String, XdsListenerPlan>),
    Cds(BTreeMap<String, XdsClusterPlan>),
    Rds(BTreeMap<String, XdsRouteTablePlan>),
    Eds(HashMap<String, Vec<UpstreamInstance>>),
    Sds(BTreeMap<String, XdsSecretPlan>),
}

enum XdsDeltaPolicyTranslation {
    #[cfg(feature = "xds-client-extensions")]
    Ecds {
        cache: DeltaResourceCache,
        names: BTreeSet<String>,
        changed: bool,
    },
    Lds {
        cache: DeltaResourceCache,
        listeners: BTreeMap<String, XdsListenerPlan>,
        changed: bool,
    },
    Cds {
        cache: DeltaResourceCache,
        clusters: BTreeMap<String, XdsClusterPlan>,
        changed: bool,
    },
    Rds {
        cache: DeltaResourceCache,
        routes: BTreeMap<String, XdsRouteTablePlan>,
        changed: bool,
    },
    Eds {
        cache: DeltaResourceCache,
        endpoints: HashMap<String, Vec<UpstreamInstance>>,
        changed: bool,
    },
    Sds {
        cache: DeltaResourceCache,
        secrets: BTreeMap<String, XdsSecretPlan>,
        changed: bool,
    },
}

/// 业务作用：维护 CDS/RDS/EDS Delta ADS stream，把增量先合并成每 type accepted cache，再复用同一依赖闭包与 Snapshot writer。
///
/// 参数说明：
/// - `cfg`：是 Delta bootstrap
/// - `policy`：跨重连保存资源/version/TTL/LKG
/// - `runtime`：是发布权威
/// - `status`：输出 ACK/NACK、warming、TTL 和 applied fingerprint。
///
/// 返回：stream/transport 失败时返回供外层退避；坏增量在本 stream NACK 且原 cache/Snapshot 不变。
async fn run_delta_policy_stream(
    cfg: &XdsCfg,
    policy: &mut XdsPolicySession,
    runtime: &XdsSnapshotRuntime,
    status: Arc<XdsStatus>,
) -> Result<()> {
    let channel = connect_channel(cfg).await?;
    status.mark_syncing();
    let request_capacity = cfg.limits.max_apply_queue.max(1).saturating_add(6);
    let (request_tx, request_rx) = mpsc::channel(request_capacity);
    if policy.listener_owned {
        request_tx
            .send(delta_request(
                LDS_TYPE_URL,
                vec!["*".to_owned()],
                Vec::new(),
                policy.delta_lds.initial_versions(),
                Some(build_node(cfg)),
                String::new(),
                None,
            ))
            .await
            .context("queue initial Delta LDS request")?;
    }
    request_tx
        .send(delta_request(
            CDS_TYPE_URL,
            vec!["*".to_owned()],
            Vec::new(),
            policy.delta_cds.initial_versions(),
            (!policy.listener_owned).then(|| build_node(cfg)),
            String::new(),
            None,
        ))
        .await
        .context("queue initial Delta CDS request")?;
    if !policy.route_names.is_empty() {
        request_tx
            .send(delta_request(
                RDS_TYPE_URL,
                policy.resource_names(RDS_TYPE_URL)?,
                Vec::new(),
                policy.delta_rds.initial_versions(),
                None,
                String::new(),
                None,
            ))
            .await
            .context("queue initial Delta RDS request")?;
    }
    if !policy.specs.is_empty() {
        request_tx
            .send(delta_request(
                EDS_TYPE_URL,
                policy.resource_names(EDS_TYPE_URL)?,
                Vec::new(),
                policy.delta_eds.initial_versions(),
                None,
                String::new(),
                None,
            ))
            .await
            .context("queue restored Delta EDS request")?;
    }
    if policy.secret_owned && !policy.secret_names.is_empty() {
        request_tx
            .send(delta_request(
                SDS_TYPE_URL,
                policy.resource_names(SDS_TYPE_URL)?,
                Vec::new(),
                policy.delta_sds.initial_versions(),
                None,
                String::new(),
                None,
            ))
            .await
            .context("queue restored Delta SDS request")?;
    }

    #[cfg(feature = "xds-client-extensions")]
    if !policy.extension_names.is_empty() {
        request_tx
            .send(delta_request(
                ECDS_TYPE_URL,
                policy.resource_names(ECDS_TYPE_URL)?,
                Vec::new(),
                policy.delta_ecds.initial_versions(),
                None,
                String::new(),
                None,
            ))
            .await
            .context("queue restored Delta ECDS request")?;
    }

    let mut grpc = Grpc::new(channel)
        .max_decoding_message_size(cfg.limits.max_response_bytes)
        .max_encoding_message_size(1024 * 1024);
    grpc.ready()
        .await
        .context("Delta ADS gRPC service not ready")?;
    let request = tonic::Request::new(ReceiverStream::new(request_rx));
    let path = http::uri::PathAndQuery::from_static(ADS_DELTA_PATH);
    let codec = tonic_prost::ProstCodec::<DeltaDiscoveryRequest, DeltaDiscoveryResponse>::default();
    let mut responses = grpc
        .streaming(request, path, codec)
        .await
        .context("open ADS DeltaAggregatedResources")?
        .into_inner();
    let warming_timeout =
        parse_duration(&cfg.limits.warming_timeout).unwrap_or_else(|| Duration::from_secs(60));

    loop {
        let response = if let Some(deadline) = delta_policy_deadline(policy, warming_timeout) {
            tokio::select! {
                response = responses.message() => response.context("read Delta ADS response")?,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    let subscriptions = apply_delta_policy_timers(
                        policy,
                        runtime,
                        status.as_ref(),
                        &cfg.limits,
                        warming_timeout,
                    ).await?;
                    for (type_url, subscribe, unsubscribe) in subscriptions {
                        request_tx.send(delta_request(
                            type_url,
                            subscribe,
                            unsubscribe,
                            HashMap::new(),
                            None,
                            String::new(),
                            None,
                        )).await.context("queue TTL-derived Delta policy subscription")?;
                    }
                    continue;
                }
            }
        } else {
            responses
                .message()
                .await
                .context("read Delta ADS response")?
        };
        let Some(response) = response else {
            break;
        };
        let response_type = response.type_url.clone();
        let system_version = response.system_version_info.clone();
        let nonce = response.nonce.clone();
        let response_bytes = response.encoded_len();
        status.mark_received();
        let limits = cfg.limits.clone();
        let specs = policy.specs.clone();
        let allowed_routes = policy.route_names.clone();
        let allowed_secrets = policy.secret_names.clone();
        #[cfg(feature = "xds-client-extensions")]
        let allowed_extensions = policy.extension_names.clone();
        #[cfg(feature = "xds-client-extensions")]
        let current_ecds = policy.delta_ecds.clone();
        let current_lds = policy.delta_lds.clone();
        let current_cds = policy.delta_cds.clone();
        let current_rds = policy.delta_rds.clone();
        let current_eds = policy.delta_eds.clone();
        let current_sds = policy.delta_sds.clone();
        let validation_base = runtime.snap.load_full();
        let validation_path = runtime.cfg_path.clone();
        status.apply_queue_depth.store(1, Ordering::Release);
        let translated_task = tokio::task::spawn_blocking(move || {
            let now = Instant::now();
            match response.type_url.as_str() {
                #[cfg(feature = "xds-client-extensions")]
                ECDS_TYPE_URL => {
                    anyhow::ensure!(
                        !allowed_extensions.is_empty(),
                        "Delta ECDS arrived before LDS subscription"
                    );
                    validate_delta_response_envelope(&response, ECDS_TYPE_URL, &limits)?;
                    let response = filter_delta_named_response(&response, &allowed_extensions);
                    let (cache, changed) =
                        current_ecds.apply_response(&response, ECDS_TYPE_URL, &limits, now)?;
                    let changed_names = translate_ecds_resources(
                        &delta_payloads(&response),
                        &allowed_extensions,
                        &limits,
                    )?;
                    validate_delta_translated_names(&response, changed_names.iter())?;
                    let names = translate_ecds_resources(
                        &cache.resource_values(),
                        &allowed_extensions,
                        &limits,
                    )?;
                    Ok(XdsDeltaPolicyTranslation::Ecds {
                        cache,
                        names,
                        changed,
                    })
                }
                LDS_TYPE_URL => {
                    let (cache, changed) =
                        current_lds.apply_response(&response, LDS_TYPE_URL, &limits, now)?;
                    let changed_plans =
                        translate_lds_resources(&delta_payloads(&response), &limits)?;
                    validate_delta_translated_names(&response, changed_plans.keys())?;
                    let listeners = translate_lds_resources(&cache.resource_values(), &limits)?;
                    Ok(XdsDeltaPolicyTranslation::Lds {
                        cache,
                        listeners,
                        changed,
                    })
                }
                CDS_TYPE_URL => {
                    let (cache, changed) =
                        current_cds.apply_response(&response, CDS_TYPE_URL, &limits, now)?;
                    let changed_plans =
                        translate_cds_resources(&delta_payloads(&response), &limits)?;
                    validate_delta_translated_names(&response, changed_plans.keys())?;
                    let clusters = translate_cds_resources(&cache.resource_values(), &limits)?;
                    validate_cds_native(validation_base.as_ref(), &clusters, &validation_path)?;
                    Ok(XdsDeltaPolicyTranslation::Cds {
                        cache,
                        clusters,
                        changed,
                    })
                }
                RDS_TYPE_URL => {
                    validate_delta_response_envelope(&response, RDS_TYPE_URL, &limits)?;
                    let response = filter_delta_named_response(&response, &allowed_routes);
                    let (cache, changed) =
                        current_rds.apply_response(&response, RDS_TYPE_URL, &limits, now)?;
                    let changed_plans = translate_rds_resources(
                        &delta_payloads(&response),
                        &allowed_routes,
                        &limits,
                    )?;
                    validate_delta_translated_names(&response, changed_plans.keys())?;
                    let routes = translate_rds_resources(
                        &cache.resource_values(),
                        &allowed_routes,
                        &limits,
                    )?;
                    validate_rds_native(&routes, &validation_path)?;
                    Ok(XdsDeltaPolicyTranslation::Rds {
                        cache,
                        routes,
                        changed,
                    })
                }
                EDS_TYPE_URL => {
                    anyhow::ensure!(
                        !specs.is_empty(),
                        "Delta EDS response arrived before CDS subscription"
                    );
                    validate_delta_response_envelope(&response, EDS_TYPE_URL, &limits)?;
                    let subscribed = specs
                        .iter()
                        .map(|spec| spec.cluster_name.clone())
                        .collect::<BTreeSet<_>>();
                    let response = filter_delta_named_response(&response, &subscribed);
                    let (cache, changed) =
                        current_eds.apply_response(&response, EDS_TYPE_URL, &limits, now)?;
                    validate_delta_eds_names(&response, &specs, &limits)?;
                    let endpoints = translate_eds_resource_set(
                        &cache.resource_values(),
                        &specs,
                        &limits,
                        true,
                    )?;
                    Ok(XdsDeltaPolicyTranslation::Eds {
                        cache,
                        endpoints,
                        changed,
                    })
                }
                SDS_TYPE_URL => {
                    anyhow::ensure!(
                        !allowed_secrets.is_empty(),
                        "Delta SDS response arrived before LDS subscription"
                    );
                    validate_delta_response_envelope(&response, SDS_TYPE_URL, &limits)?;
                    let response = filter_delta_named_response(&response, &allowed_secrets);
                    let (cache, changed) =
                        current_sds.apply_response(&response, SDS_TYPE_URL, &limits, now)?;
                    let changed_plans =
                        translate_sds_resources(&delta_payloads(&response), &limits)?;
                    validate_delta_translated_names(&response, changed_plans.keys())?;
                    let secrets = translate_sds_resources(&cache.resource_values(), &limits)?;
                    Ok(XdsDeltaPolicyTranslation::Sds {
                        cache,
                        secrets,
                        changed,
                    })
                }
                other => bail!("unsupported Delta ADS resource type `{other}`"),
            }
        })
        .await;
        status.apply_queue_depth.store(0, Ordering::Release);
        let translated = translated_task.context("join Delta xDS policy translation task")?;

        match translated {
            Ok(translated) => {
                let mut candidate = policy.clone();
                let mut eds_subscription = None;
                let mut rds_subscription = None;
                let mut sds_subscription = None;
                #[cfg(feature = "xds-client-extensions")]
                let old_extensions = candidate.extension_names.clone();
                let (changed, outcome) = match translated {
                    XdsDeltaPolicyTranslation::Lds {
                        cache,
                        listeners,
                        changed,
                    } => {
                        candidate.delta_lds = cache;
                        if changed {
                            let old_routes = candidate.route_names.clone();
                            let old_secrets = candidate.secret_names.clone();
                            let (routes_changed, secrets_changed, _) =
                                candidate.refresh_listener_dependencies(&listeners);
                            if routes_changed {
                                rds_subscription = Some(delta_subscription_diff(
                                    &old_routes,
                                    &candidate.route_names,
                                ));
                            }
                            if secrets_changed {
                                sds_subscription = Some(delta_subscription_diff(
                                    &old_secrets,
                                    &candidate.secret_names,
                                ));
                            }
                            (
                                true,
                                Some(candidate.cache.accept_listeners(listeners, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                    XdsDeltaPolicyTranslation::Cds {
                        cache,
                        clusters,
                        changed,
                    } => {
                        candidate.delta_cds = cache;
                        if changed {
                            let old_names = candidate
                                .specs
                                .iter()
                                .map(|spec| spec.cluster_name.clone())
                                .collect::<BTreeSet<_>>();
                            let specs_changed = candidate.refresh_eds_specs(&clusters);
                            let new_names = candidate
                                .specs
                                .iter()
                                .map(|spec| spec.cluster_name.clone())
                                .collect::<BTreeSet<_>>();
                            if specs_changed {
                                let unsubscribe = old_names
                                    .difference(&new_names)
                                    .cloned()
                                    .collect::<Vec<_>>();
                                let mut subscribe = new_names
                                    .difference(&old_names)
                                    .cloned()
                                    .collect::<Vec<_>>();
                                if subscribe.is_empty() && unsubscribe.is_empty() {
                                    subscribe.extend(new_names.iter().cloned());
                                }
                                eds_subscription = Some((subscribe, unsubscribe));
                            }
                            (
                                true,
                                Some(candidate.cache.accept_clusters(clusters, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                    XdsDeltaPolicyTranslation::Rds {
                        cache,
                        routes,
                        changed,
                    } => {
                        candidate.delta_rds = cache;
                        if changed {
                            (
                                true,
                                Some(candidate.cache.accept_routes(routes, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                    XdsDeltaPolicyTranslation::Eds {
                        cache,
                        endpoints,
                        changed,
                    } => {
                        candidate.delta_eds = cache;
                        if changed {
                            candidate.endpoints = endpoints;
                            let observed = candidate
                                .specs
                                .iter()
                                .filter(|spec| {
                                    candidate.delta_eds.observed.contains(&spec.cluster_name)
                                })
                                .map(|spec| spec.cluster_name.clone())
                                .collect::<BTreeSet<_>>();
                            (
                                true,
                                Some(candidate.cache.accept_endpoints(observed, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                    XdsDeltaPolicyTranslation::Sds {
                        cache,
                        secrets,
                        changed,
                    } => {
                        candidate.delta_sds = cache;
                        if changed {
                            (
                                true,
                                Some(candidate.cache.accept_secrets(secrets, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                    #[cfg(feature = "xds-client-extensions")]
                    XdsDeltaPolicyTranslation::Ecds {
                        cache,
                        names,
                        changed,
                    } => {
                        candidate.delta_ecds = cache;
                        if changed {
                            (
                                true,
                                Some(candidate.cache.accept_extensions(names, Instant::now())),
                            )
                        } else {
                            (false, None)
                        }
                    }
                };

                if changed {
                    match outcome.expect("changed Delta response reconciles policy") {
                        XdsPolicyOutcome::Active(active) => {
                            let fingerprint = policy_fingerprint(&active, &candidate.endpoints);
                            let resources = policy_resource_counts(&active, &candidate.endpoints);
                            if status.content_unchanged(&fingerprint) {
                                status.mark_policy_duplicate(
                                    &response_type,
                                    &system_version,
                                    &nonce,
                                    &resources,
                                    fingerprint,
                                );
                            } else {
                                if let Err(error) =
                                    apply_policy_generation(&active, &candidate.endpoints, runtime)
                                        .await
                                {
                                    let message = truncate_error(&format!("{error:#}"));
                                    tracing::warn!(type_url = %response_type, nonce = %nonce, error = %message, "xDS Delta policy apply NACK");
                                    status.mark_policy_rejected(
                                        &response_type,
                                        &nonce,
                                        &message,
                                        response_bytes,
                                    );
                                    request_tx
                                        .send(delta_request(
                                            &response_type,
                                            Vec::new(),
                                            Vec::new(),
                                            HashMap::new(),
                                            None,
                                            nonce.clone(),
                                            Some(RpcStatus {
                                                code: INVALID_ARGUMENT_CODE,
                                                message,
                                                details: Vec::new(),
                                            }),
                                        ))
                                        .await
                                        .context("queue Delta xDS policy apply NACK")?;
                                    continue;
                                }
                                status.mark_policy_accepted(
                                    &response_type,
                                    &system_version,
                                    &nonce,
                                    Some(&resources),
                                    Some(&fingerprint),
                                    None,
                                );
                            }
                            candidate.active_endpoints = candidate.endpoints.clone();
                        }
                        XdsPolicyOutcome::Warming {
                            missing,
                            protection,
                            ..
                        } => {
                            // 明确撤回的扩展证明优先关闭入口；只有保护发布完成后才确认该控制消息。
                            if let Some(protected) = protection {
                                apply_policy_generation(
                                    &protected,
                                    &candidate.active_endpoints,
                                    runtime,
                                )
                                .await?;
                                status.mark_policy_ttl_applied(
                                    0,
                                    &policy_resource_counts(
                                        &protected,
                                        &candidate.active_endpoints,
                                    ),
                                    policy_fingerprint(&protected, &candidate.active_endpoints),
                                );
                            }
                            status.mark_policy_accepted(
                                &response_type,
                                &system_version,
                                &nonce,
                                None,
                                None,
                                Some(&missing),
                            );
                        }
                    }
                } else {
                    status.mark_delta_duplicate(&response_type, &system_version, &nonce);
                }
                #[cfg(feature = "xds-client-extensions")]
                let extension_subscription =
                    delta_subscription_diff(&old_extensions, &candidate.extension_names);
                *policy = candidate;
                request_tx
                    .send(delta_request(
                        &response_type,
                        Vec::new(),
                        Vec::new(),
                        HashMap::new(),
                        None,
                        nonce,
                        None,
                    ))
                    .await
                    .context("queue Delta xDS policy ACK")?;
                if let Some((subscribe, unsubscribe)) = eds_subscription {
                    if !subscribe.is_empty() || !unsubscribe.is_empty() {
                        request_tx
                            .send(delta_request(
                                EDS_TYPE_URL,
                                subscribe,
                                unsubscribe,
                                HashMap::new(),
                                None,
                                String::new(),
                                None,
                            ))
                            .await
                            .context("queue CDS-derived Delta EDS subscription")?;
                    }
                }
                if let Some((subscribe, unsubscribe)) = rds_subscription {
                    if !subscribe.is_empty() || !unsubscribe.is_empty() {
                        request_tx
                            .send(delta_request(
                                RDS_TYPE_URL,
                                subscribe,
                                unsubscribe,
                                HashMap::new(),
                                None,
                                String::new(),
                                None,
                            ))
                            .await
                            .context("queue LDS-derived Delta RDS subscription")?;
                    }
                }
                if let Some((subscribe, unsubscribe)) = sds_subscription {
                    if !subscribe.is_empty() || !unsubscribe.is_empty() {
                        request_tx
                            .send(delta_request(
                                SDS_TYPE_URL,
                                subscribe,
                                unsubscribe,
                                HashMap::new(),
                                None,
                                String::new(),
                                None,
                            ))
                            .await
                            .context("queue LDS-derived Delta SDS subscription")?;
                    }
                }
                #[cfg(feature = "xds-client-extensions")]
                if !extension_subscription.0.is_empty() || !extension_subscription.1.is_empty() {
                    request_tx
                        .send(delta_request(
                            ECDS_TYPE_URL,
                            extension_subscription.0,
                            extension_subscription.1,
                            HashMap::new(),
                            None,
                            String::new(),
                            None,
                        ))
                        .await
                        .context("queue LDS-derived Delta ECDS subscription")?;
                }
            }
            Err(error) => {
                let code = if error.downcast_ref::<XdsResourceExhausted>().is_some() {
                    RESOURCE_EXHAUSTED_CODE
                } else {
                    INVALID_ARGUMENT_CODE
                };
                let message = truncate_error(&format!("{error:#}"));
                tracing::warn!(type_url = %response_type, nonce = %nonce, error = %message, "xDS Delta policy response NACK");
                status.mark_policy_rejected(&response_type, &nonce, &message, response_bytes);
                request_tx
                    .send(delta_request(
                        if response_type.is_empty() {
                            EDS_TYPE_URL
                        } else {
                            &response_type
                        },
                        Vec::new(),
                        Vec::new(),
                        HashMap::new(),
                        None,
                        nonce,
                        Some(RpcStatus {
                            code,
                            message,
                            details: Vec::new(),
                        }),
                    ))
                    .await
                    .context("queue Delta xDS policy NACK")?;
            }
        }
    }
    bail!("Delta ADS server closed response stream")
}

/// 业务作用：提取 Delta response 中真正携带 payload 的 Any，heartbeat 不进入 translator。
///
/// 参数说明：
/// - `response`：是单 type 增量。
///
/// 返回：保持 wrapper 顺序的 Any clone 列表。
fn delta_payloads(response: &DeltaDiscoveryResponse) -> Vec<Any> {
    response
        .resources
        .iter()
        .filter_map(|resource| resource.resource.clone())
        .collect()
}

/// 业务作用：校验 CDS/RDS wrapper.name 与内层 protobuf name 完全一致，保证 version cache 不串资源。
///
/// 参数说明：
/// - `response`：提供 wrapper
/// - `translated_names`：是相同 payload 经过严格 translator 的键。
///
/// 返回：两个 name 集完全一致时成功；heartbeat 不参与比较。
fn validate_delta_translated_names<'a>(
    response: &DeltaDiscoveryResponse,
    translated_names: impl Iterator<Item = &'a String>,
) -> Result<()> {
    let wrappers = response
        .resources
        .iter()
        .filter(|resource| resource.resource.is_some())
        .map(|resource| resource.name.clone())
        .collect::<BTreeSet<_>>();
    let translated = translated_names.cloned().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        wrappers == translated,
        "Delta wrapper name does not match inner xDS resource name"
    );
    Ok(())
}

/// 业务作用：生成 active policy 的固定 CDS/RDS/EDS 计数，供 status/metrics 在 SotW 与 Delta 共用。
///
/// 参数说明：
/// - `active`：是已发布闭包
/// - `endpoints`：是同代 logical EDS 表。
///
/// 返回：已实现资源域的固定低基数计数，不以资源名建立指标维度。
fn policy_resource_counts(
    active: &XdsPolicySnapshot,
    endpoints: &HashMap<String, Vec<UpstreamInstance>>,
) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("lds".to_owned(), active.listeners.len() as u64),
        ("cds".to_owned(), active.clusters.len() as u64),
        ("rds".to_owned(), active.routes.len() as u64),
        ("eds".to_owned(), endpoints.len() as u64),
        ("sds".to_owned(), active.secrets.len() as u64),
        #[cfg(feature = "xds-client-extensions")]
        (
            "ecds".to_owned(),
            active
                .listeners
                .values()
                .filter_map(|listener| listener.extension_name.as_ref())
                .collect::<BTreeSet<_>>()
                .len() as u64,
        ),
    ])
}

/// 业务作用：计算 Delta named subscription 的最小增删集，listener 依赖移除时显式交还资源所有权。
///
/// 参数说明：
/// - `old`：是同一 resource type 的稳定名字集合。
/// - `new`：是同一 resource type 的稳定名字集合。
///
/// 返回：先 subscribe、后 unsubscribe 使用的排序向量；集合相同则均为空。
fn delta_subscription_diff(
    old: &BTreeSet<String>,
    new: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    (
        new.difference(old).cloned().collect(),
        old.difference(new).cloned().collect(),
    )
}

/// 业务作用：合并 dependency warming 与三个 Delta type 的最早 TTL，receive loop 只维护一个唤醒点。
///
/// 参数说明：
/// - `policy`：持有全部单调 deadline
/// - `warming_timeout`：是 bootstrap 上限。
///
/// 返回：存在任一待处理 timer 时返回最早点，否则返回 None。
fn delta_policy_deadline(policy: &XdsPolicySession, warming_timeout: Duration) -> Option<Instant> {
    [
        policy.cache.warming_deadline(warming_timeout),
        policy.delta_lds.next_expiry(),
        policy.delta_cds.next_expiry(),
        policy.delta_rds.next_expiry(),
        policy.delta_eds.next_expiry(),
        policy.delta_sds.next_expiry(),
        #[cfg(feature = "xds-client-extensions")]
        policy.delta_ecds.next_expiry(),
    ]
    .into_iter()
    .flatten()
    .min()
}

/// 业务作用：处理无新 response 时到期的 warming/TTL，并在完整闭包下原子发布资源 removal。
///
/// 参数说明：
/// - `policy`：是跨重连 accepted cache
/// - `runtime`：是 single-writer
/// - `status`：是观测
/// - `limits`：是 bootstrap 硬门。
/// - `warming_timeout`：是 bootstrap 硬门。
///
/// 返回：TTL 导致的 RDS/EDS/SDS named subscription 变更列表；断线退避调用方可忽略并在重连恢复。
async fn apply_delta_policy_timers(
    policy: &mut XdsPolicySession,
    runtime: &XdsSnapshotRuntime,
    status: &XdsStatus,
    limits: &crate::config::model::XdsLimitsCfg,
    warming_timeout: Duration,
) -> Result<Vec<(&'static str, Vec<String>, Vec<String>)>> {
    let now = Instant::now();
    if policy
        .cache
        .warming_deadline(warming_timeout)
        .is_some_and(|deadline| deadline <= now)
        && policy.cache.mark_warming_timeout_reported()
    {
        status.mark_warming_timeout();
        tracing::warn!("xDS Delta dependency warming deadline exceeded; retaining prior LKG");
    }

    let mut candidate = policy.clone();
    let expired_lds = candidate.delta_lds.expire_due(now, false);
    let expired_cds = candidate.delta_cds.expire_due(now, false);
    let expired_rds = candidate.delta_rds.expire_due(now, false);
    let expired_eds = candidate.delta_eds.expire_due(now, true);
    let expired_sds = candidate.delta_sds.expire_due(now, false);
    #[cfg(feature = "xds-client-extensions")]
    let expired_ecds = candidate.delta_ecds.expire_due(now, false).len();
    #[cfg(not(feature = "xds-client-extensions"))]
    let expired_ecds = 0;
    let expired = expired_lds
        .len()
        .saturating_add(expired_cds.len())
        .saturating_add(expired_rds.len())
        .saturating_add(expired_eds.len())
        .saturating_add(expired_sds.len())
        .saturating_add(expired_ecds);
    if expired == 0 {
        return Ok(Vec::new());
    }

    let mut subscriptions = Vec::new();
    if candidate.listener_owned && !expired_lds.is_empty() {
        let listeners = translate_lds_resources(&candidate.delta_lds.resource_values(), limits)?;
        let old_routes = candidate.route_names.clone();
        let old_secrets = candidate.secret_names.clone();
        #[cfg(feature = "xds-client-extensions")]
        let old_extensions = candidate.extension_names.clone();
        let (routes_changed, secrets_changed, _) =
            candidate.refresh_listener_dependencies(&listeners);
        #[cfg(feature = "xds-client-extensions")]
        if old_extensions != candidate.extension_names {
            let (subscribe, unsubscribe) =
                delta_subscription_diff(&old_extensions, &candidate.extension_names);
            subscriptions.push((ECDS_TYPE_URL, subscribe, unsubscribe));
        }
        if routes_changed {
            let (subscribe, unsubscribe) =
                delta_subscription_diff(&old_routes, &candidate.route_names);
            subscriptions.push((RDS_TYPE_URL, subscribe, unsubscribe));
        }
        if secrets_changed {
            let (subscribe, unsubscribe) =
                delta_subscription_diff(&old_secrets, &candidate.secret_names);
            subscriptions.push((SDS_TYPE_URL, subscribe, unsubscribe));
        }
        let _ = candidate.cache.accept_listeners(listeners, now);
    }
    let cds_resources = candidate.delta_cds.resource_values();
    let rds_resources = candidate.delta_rds.resource_values();
    let allowed_routes = candidate.route_names.clone();
    let base = runtime.snap.load_full();
    let cfg_path = runtime.cfg_path.clone();
    let limits_owned = limits.clone();
    let (clusters, routes) = tokio::task::spawn_blocking(move || {
        let clusters = translate_cds_resources(&cds_resources, &limits_owned)?;
        validate_cds_native(base.as_ref(), &clusters, &cfg_path)?;
        let routes = translate_rds_resources(&rds_resources, &allowed_routes, &limits_owned)?;
        validate_rds_native(&routes, &cfg_path)?;
        Ok::<_, anyhow::Error>((clusters, routes))
    })
    .await
    .context("join Delta CDS/RDS TTL translation task")??;

    let old_names = candidate
        .specs
        .iter()
        .map(|spec| spec.cluster_name.clone())
        .collect::<BTreeSet<_>>();
    let specs_changed = candidate.refresh_eds_specs(&clusters);
    let new_names = candidate
        .specs
        .iter()
        .map(|spec| spec.cluster_name.clone())
        .collect::<BTreeSet<_>>();
    let eds_resources = candidate.delta_eds.resource_values();
    let specs = candidate.specs.clone();
    let limits_owned = limits.clone();
    let endpoints = tokio::task::spawn_blocking(move || {
        translate_eds_resource_set(&eds_resources, &specs, &limits_owned, true)
    })
    .await
    .context("join Delta EDS TTL translation task")??;
    candidate.endpoints = endpoints;
    let _ = candidate.cache.accept_clusters(clusters, now);
    let _ = candidate.cache.accept_routes(routes, now);
    if candidate.secret_owned && !expired_sds.is_empty() {
        let secrets = translate_sds_resources(&candidate.delta_sds.resource_values(), limits)?;
        let _ = candidate.cache.accept_secrets(secrets, now);
    }
    #[cfg(feature = "xds-client-extensions")]
    if expired_ecds != 0 {
        let names = translate_ecds_resources(
            &candidate.delta_ecds.resource_values(),
            &candidate.extension_names,
            limits,
        )?;
        let _ = candidate.cache.accept_extensions(names, now);
    }
    let observed = candidate
        .specs
        .iter()
        .filter(|spec| candidate.delta_eds.observed.contains(&spec.cluster_name))
        .map(|spec| spec.cluster_name.clone())
        .collect::<BTreeSet<_>>();
    let outcome = candidate.cache.accept_endpoints(observed, now);
    match outcome {
        XdsPolicyOutcome::Active(active) => {
            apply_policy_generation(&active, &candidate.endpoints, runtime).await?;
            let fingerprint = policy_fingerprint(&active, &candidate.endpoints);
            let resources = policy_resource_counts(&active, &candidate.endpoints);
            status.mark_policy_ttl_applied(expired, &resources, fingerprint);
            candidate.active_endpoints = candidate.endpoints.clone();
        }
        XdsPolicyOutcome::Warming {
            missing,
            protection,
            ..
        } => {
            if let Some(protected) = protection {
                // TTL 是执行权威的绝对截止点；先撤路，再发布等待状态，不能用 LKG 续期。
                apply_policy_generation(&protected, &candidate.active_endpoints, runtime).await?;
                status.mark_policy_ttl_applied(
                    0,
                    &policy_resource_counts(&protected, &candidate.active_endpoints),
                    policy_fingerprint(&protected, &candidate.active_endpoints),
                );
            }
            status.mark_ttl_warming(expired, &missing);
        }
    }
    *policy = candidate;

    if specs_changed {
        let unsubscribe = old_names
            .difference(&new_names)
            .cloned()
            .collect::<Vec<_>>();
        let mut subscribe = new_names
            .difference(&old_names)
            .cloned()
            .collect::<Vec<_>>();
        if subscribe.is_empty() && unsubscribe.is_empty() {
            subscribe.extend(new_names.iter().cloned());
        }
        subscriptions.push((EDS_TYPE_URL, subscribe, unsubscribe));
    }
    Ok(subscriptions)
}

/// 业务作用：维护一代 CDS/RDS/EDS ADS stream，合法 warming 版本 ACK，完整闭包才发布 Snapshot。
///
/// 参数说明：
/// - `cfg`：是 bootstrap
/// - `policy`：跨重连保留 accepted/LKG
/// - `runtime`：是唯一发布链
/// - `status`：对外暴露按 type 的 ACK/NACK 与 readiness。
///
/// 返回：stream 关闭或传输失败时返回错误供外层退避重连；资源错误留在 stream 内 NACK。
async fn run_policy_stream(
    cfg: &XdsCfg,
    policy: &mut XdsPolicySession,
    runtime: &XdsSnapshotRuntime,
    status: Arc<XdsStatus>,
) -> Result<()> {
    let channel = connect_channel(cfg).await?;
    status.mark_syncing();
    let request_capacity = cfg.limits.max_apply_queue.max(1).saturating_add(6);
    let (request_tx, request_rx) = mpsc::channel(request_capacity);
    if policy.listener_owned {
        request_tx
            .send(DiscoveryRequest {
                version_info: status.accepted_version_for(LDS_TYPE_URL),
                node: Some(build_node(cfg)),
                resource_names: Vec::new(),
                type_url: LDS_TYPE_URL.to_owned(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .await
            .context("queue initial LDS DiscoveryRequest")?;
    }
    request_tx
        .send(DiscoveryRequest {
            version_info: status.accepted_version_for(CDS_TYPE_URL),
            node: (!policy.listener_owned).then(|| build_node(cfg)),
            resource_names: Vec::new(),
            type_url: CDS_TYPE_URL.to_owned(),
            response_nonce: String::new(),
            error_detail: None,
        })
        .await
        .context("queue initial CDS DiscoveryRequest")?;
    if !policy.route_names.is_empty() {
        request_tx
            .send(DiscoveryRequest {
                version_info: status.accepted_version_for(RDS_TYPE_URL),
                node: None,
                resource_names: policy.resource_names(RDS_TYPE_URL)?,
                type_url: RDS_TYPE_URL.to_owned(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .await
            .context("queue initial RDS DiscoveryRequest")?;
    }
    if !policy.specs.is_empty() {
        request_tx
            .send(DiscoveryRequest {
                version_info: status.accepted_version_for(EDS_TYPE_URL),
                node: None,
                resource_names: policy.resource_names(EDS_TYPE_URL)?,
                type_url: EDS_TYPE_URL.to_owned(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .await
            .context("queue restored EDS DiscoveryRequest")?;
    }
    if policy.secret_owned && !policy.secret_names.is_empty() {
        request_tx
            .send(DiscoveryRequest {
                version_info: status.accepted_version_for(SDS_TYPE_URL),
                node: None,
                resource_names: policy.resource_names(SDS_TYPE_URL)?,
                type_url: SDS_TYPE_URL.to_owned(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .await
            .context("queue restored SDS DiscoveryRequest")?;
    }
    #[cfg(feature = "xds-client-extensions")]
    if !policy.extension_names.is_empty() {
        request_tx
            .send(DiscoveryRequest {
                version_info: status.accepted_version_for(ECDS_TYPE_URL),
                node: None,
                resource_names: policy.resource_names(ECDS_TYPE_URL)?,
                type_url: ECDS_TYPE_URL.to_owned(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .await
            .context("queue restored ECDS DiscoveryRequest")?;
    }

    let mut grpc = Grpc::new(channel)
        .max_decoding_message_size(cfg.limits.max_response_bytes)
        .max_encoding_message_size(1024 * 1024);
    grpc.ready().await.context("ADS gRPC service not ready")?;
    let request = tonic::Request::new(ReceiverStream::new(request_rx));
    let path = http::uri::PathAndQuery::from_static(ADS_SOTW_PATH);
    let codec = tonic_prost::ProstCodec::<DiscoveryRequest, DiscoveryResponse>::default();
    let mut responses = grpc
        .streaming(request, path, codec)
        .await
        .context("open ADS StreamAggregatedResources")?
        .into_inner();

    let warming_timeout =
        parse_duration(&cfg.limits.warming_timeout).unwrap_or_else(|| Duration::from_secs(60));
    loop {
        let response = if let Some(deadline) = policy.cache.warming_deadline(warming_timeout) {
            tokio::select! {
                response = responses.message() => response.context("read ADS response")?,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    // 合法候选已 ACK 但依赖长期缺席时只降低新鲜度并保留 LKG；不能发送无对应
                    // response 的伪 NACK，也不能在已过期 deadline 上空转放大 CPU/指标。
                    if policy.cache.mark_warming_timeout_reported() {
                        status.mark_warming_timeout();
                        tracing::warn!("xDS dependency warming deadline exceeded; retaining prior LKG");
                    }
                    continue;
                }
            }
        } else {
            responses.message().await.context("read ADS response")?
        };
        let Some(response) = response else {
            break;
        };
        let response_type = response.type_url.clone();
        let version = response.version_info.clone();
        let nonce = response.nonce.clone();
        let response_bytes = response.encoded_len();
        status.mark_received();
        let limits = cfg.limits.clone();
        let specs = policy.specs.clone();
        let allowed_routes = policy.route_names.clone();
        let allowed_secrets = policy.secret_names.clone();
        #[cfg(feature = "xds-client-extensions")]
        let allowed_extensions = policy.extension_names.clone();
        let validation_base = runtime.snap.load_full();
        let validation_path = runtime.cfg_path.clone();
        status.apply_queue_depth.store(1, Ordering::Release);
        let translated_task = tokio::task::spawn_blocking(move || {
            validate_discovery_response_envelope(&response, &limits)?;
            match response.type_url.as_str() {
                #[cfg(feature = "xds-client-extensions")]
                ECDS_TYPE_URL => {
                    anyhow::ensure!(
                        !allowed_extensions.is_empty(),
                        "ECDS arrived before LDS subscription"
                    );
                    translate_ecds_resources(&response.resources, &allowed_extensions, &limits)
                        .map(XdsPolicyTranslation::Ecds)
                }
                LDS_TYPE_URL => translate_lds_resources(&response.resources, &limits)
                    .map(XdsPolicyTranslation::Lds),
                CDS_TYPE_URL => {
                    let clusters = translate_cds_resources(&response.resources, &limits)?;
                    validate_cds_native(validation_base.as_ref(), &clusters, &validation_path)?;
                    Ok(XdsPolicyTranslation::Cds(clusters))
                }
                RDS_TYPE_URL => {
                    let routes =
                        translate_rds_resources(&response.resources, &allowed_routes, &limits)?;
                    validate_rds_native(&routes, &validation_path)?;
                    Ok(XdsPolicyTranslation::Rds(routes))
                }
                EDS_TYPE_URL => {
                    anyhow::ensure!(
                        !specs.is_empty(),
                        "EDS response arrived before CDS subscription"
                    );
                    translate_eds_response(&response, &specs, &limits)
                        .map(XdsPolicyTranslation::Eds)
                }
                SDS_TYPE_URL => {
                    anyhow::ensure!(
                        !allowed_secrets.is_empty(),
                        "SDS response arrived before LDS subscription"
                    );
                    let secrets = translate_sds_resources(&response.resources, &limits)?;
                    anyhow::ensure!(
                        secrets.keys().all(|name| allowed_secrets.contains(name)),
                        "SDS response contains an unsubscribed secret"
                    );
                    Ok(XdsPolicyTranslation::Sds(secrets))
                }
                other => bail!("unsupported ADS resource type `{other}`"),
            }
        })
        .await;
        status.apply_queue_depth.store(0, Ordering::Release);
        let translated = translated_task.context("join xDS policy translation task")?;

        match translated {
            Ok(translated) => {
                let now = std::time::Instant::now();
                let mut candidate = policy.clone();
                let mut eds_subscription_changed = false;
                let mut rds_subscription_changed = false;
                let mut sds_subscription_changed = false;
                let mut extension_subscription_changed = false;
                let outcome = match translated {
                    XdsPolicyTranslation::Lds(listeners) => {
                        (
                            rds_subscription_changed,
                            sds_subscription_changed,
                            extension_subscription_changed,
                        ) = candidate.refresh_listener_dependencies(&listeners);
                        candidate.cache.accept_listeners(listeners, now)
                    }
                    XdsPolicyTranslation::Cds(clusters) => {
                        eds_subscription_changed = candidate.refresh_eds_specs(&clusters);
                        candidate.cache.accept_clusters(clusters, now)
                    }
                    XdsPolicyTranslation::Rds(routes) => candidate.cache.accept_routes(routes, now),
                    XdsPolicyTranslation::Eds(endpoints) => {
                        candidate.endpoints = endpoints;
                        let names = candidate
                            .specs
                            .iter()
                            .map(|spec| spec.cluster_name.clone())
                            .collect::<BTreeSet<_>>();
                        candidate.cache.accept_endpoints(names, now)
                    }
                    XdsPolicyTranslation::Sds(secrets) => {
                        candidate.cache.accept_secrets(secrets, now)
                    }
                    #[cfg(feature = "xds-client-extensions")]
                    XdsPolicyTranslation::Ecds(names) => {
                        candidate.cache.accept_extensions(names, now)
                    }
                };
                match outcome {
                    XdsPolicyOutcome::Active(active) => {
                        if let Err(error) =
                            apply_policy_generation(&active, &candidate.endpoints, runtime).await
                        {
                            // listener prepare/native materialization 失败属于本 response 的应用失败；
                            // 必须 NACK 并保留 accepted cache/LKG，不能断 stream 让控制面误判超时。
                            let message = truncate_error(&format!("{error:#}"));
                            tracing::warn!(type_url = %response_type, nonce = %nonce, error = %message, "xDS policy apply NACK");
                            status.mark_policy_rejected(
                                &response_type,
                                &nonce,
                                &message,
                                response_bytes,
                            );
                            request_tx
                                .send(DiscoveryRequest {
                                    version_info: status.accepted_version_for(&response_type),
                                    node: None,
                                    resource_names: policy
                                        .resource_names(&response_type)
                                        .unwrap_or_default(),
                                    type_url: response_type.clone(),
                                    response_nonce: nonce.clone(),
                                    error_detail: Some(RpcStatus {
                                        code: INVALID_ARGUMENT_CODE,
                                        message,
                                        details: Vec::new(),
                                    }),
                                })
                                .await
                                .context("queue xDS policy apply NACK")?;
                            continue;
                        }
                        let resources = policy_resource_counts(&active, &candidate.endpoints);
                        let fingerprint = policy_fingerprint(&active, &candidate.endpoints);
                        candidate.active_endpoints = candidate.endpoints.clone();
                        *policy = candidate;
                        status.mark_policy_accepted(
                            &response_type,
                            &version,
                            &nonce,
                            Some(&resources),
                            Some(&fingerprint),
                            None,
                        );
                    }
                    XdsPolicyOutcome::Warming {
                        missing,
                        resources: _,
                        protection,
                    } => {
                        if let Some(protected) = protection {
                            // 控制面明确撤回终结器后，先关闭依赖入口，再 ACK 合法的资源删除。
                            apply_policy_generation(
                                &protected,
                                &candidate.active_endpoints,
                                runtime,
                            )
                            .await?;
                            status.mark_policy_ttl_applied(
                                0,
                                &policy_resource_counts(&protected, &candidate.active_endpoints),
                                policy_fingerprint(&protected, &candidate.active_endpoints),
                            );
                        }
                        *policy = candidate;
                        status.mark_policy_accepted(
                            &response_type,
                            &version,
                            &nonce,
                            None,
                            None,
                            Some(&missing),
                        );
                    }
                }
                let ack_names = policy.resource_names(&response_type)?;
                request_tx
                    .send(DiscoveryRequest {
                        version_info: version.clone(),
                        node: None,
                        resource_names: ack_names,
                        type_url: response_type.clone(),
                        response_nonce: nonce.clone(),
                        error_detail: None,
                    })
                    .await
                    .context("queue xDS policy ACK")?;
                if eds_subscription_changed && !policy.specs.is_empty() {
                    request_tx
                        .send(DiscoveryRequest {
                            version_info: status.accepted_version_for(EDS_TYPE_URL),
                            node: None,
                            resource_names: policy.resource_names(EDS_TYPE_URL)?,
                            type_url: EDS_TYPE_URL.to_owned(),
                            response_nonce: String::new(),
                            error_detail: None,
                        })
                        .await
                        .context("queue CDS-derived EDS subscription")?;
                }
                if rds_subscription_changed && !policy.route_names.is_empty() {
                    request_tx
                        .send(DiscoveryRequest {
                            version_info: status.accepted_version_for(RDS_TYPE_URL),
                            node: None,
                            resource_names: policy.resource_names(RDS_TYPE_URL)?,
                            type_url: RDS_TYPE_URL.to_owned(),
                            response_nonce: String::new(),
                            error_detail: None,
                        })
                        .await
                        .context("queue LDS-derived RDS subscription")?;
                }
                if sds_subscription_changed && !policy.secret_names.is_empty() {
                    request_tx
                        .send(DiscoveryRequest {
                            version_info: status.accepted_version_for(SDS_TYPE_URL),
                            node: None,
                            resource_names: policy.resource_names(SDS_TYPE_URL)?,
                            type_url: SDS_TYPE_URL.to_owned(),
                            response_nonce: String::new(),
                            error_detail: None,
                        })
                        .await
                        .context("queue LDS-derived SDS subscription")?;
                }
                if extension_subscription_changed {
                    #[cfg(feature = "xds-client-extensions")]
                    {
                        // 空命名集不能编码为 SotW wildcard；保留一个不可能通过名称门的占位订阅。
                        let names = if policy.extension_names.is_empty() {
                            vec!["!naway-unsubscribed".to_owned()]
                        } else {
                            policy.resource_names(ECDS_TYPE_URL)?
                        };
                        request_tx
                            .send(DiscoveryRequest {
                                version_info: status.accepted_version_for(ECDS_TYPE_URL),
                                node: None,
                                resource_names: names,
                                type_url: ECDS_TYPE_URL.to_owned(),
                                response_nonce: String::new(),
                                error_detail: None,
                            })
                            .await
                            .context("queue LDS-derived ECDS subscription")?;
                    }
                }
            }
            Err(error) => {
                let code = if error.downcast_ref::<XdsResourceExhausted>().is_some() {
                    RESOURCE_EXHAUSTED_CODE
                } else {
                    INVALID_ARGUMENT_CODE
                };
                let message = truncate_error(&format!("{error:#}"));
                tracing::warn!(type_url = %response_type, nonce = %nonce, error = %message, "xDS policy response NACK");
                status.mark_policy_rejected(&response_type, &nonce, &message, response_bytes);
                let resource_names = policy.resource_names(&response_type).unwrap_or_default();
                request_tx
                    .send(DiscoveryRequest {
                        version_info: status.accepted_version_for(&response_type),
                        node: None,
                        resource_names,
                        type_url: response_type.clone(),
                        response_nonce: nonce.clone(),
                        error_detail: Some(RpcStatus {
                            code,
                            message,
                            details: Vec::new(),
                        }),
                    })
                    .await
                    .context("queue xDS policy NACK")?;
            }
        }
    }
    bail!("ADS server closed response stream")
}

/// 业务作用：在共享写锁内编译并发布一份完整 CDS/RDS/EDS generation，ACK 必须发生在其后。
///
/// 参数说明：
/// - `policy`：是同一 accepted 候选
/// - `endpoints`：是同一 accepted 候选
/// - `runtime`：提供当前 base 与版本权威。
///
/// 返回：native 二次编译和 ArcSwap 发布成功返回 Ok；失败保持当前 Snapshot/版本不变。
async fn apply_policy_generation(
    policy: &crate::control::xds_resources::XdsPolicySnapshot,
    endpoints: &HashMap<String, Vec<UpstreamInstance>>,
    runtime: &XdsSnapshotRuntime,
) -> Result<()> {
    let _apply_guard = runtime.apply_coordinator.lock().await;
    let current = runtime.snap.load_full();
    anyhow::ensure!(
        current.control_plane.xds.enabled
            && current.control_plane.xds.ownership.routes == XdsResourceOwnerCfg::Xds,
        "xDS lost route ownership before apply"
    );
    let listener_owned = current.control_plane.xds.ownership.listeners == XdsResourceOwnerCfg::Xds;
    let old_version = runtime.version.load(Ordering::Relaxed);
    let next_version = old_version
        .checked_add(1)
        .context("xDS Snapshot version space exhausted")?;
    let base = current.clone();
    let policy = policy.clone();
    let endpoints = endpoints.clone();
    let cfg_path = runtime.cfg_path.clone();
    let candidate = tokio::task::spawn_blocking(move || {
        materialize_policy_snapshot(base.as_ref(), &policy, &endpoints, next_version, &cfg_path)
    })
    .await
    .context("join xDS Snapshot materialization")??;
    let prepared_listener = if listener_owned {
        let reconciler = runtime
            .listener_topology
            .as_ref()
            .context("xDS LDS ownership requires listener topology reconciler")?;
        // 候选 socket/TLS 必须在发布前全部 bind/build；prepare 失败只丢弃候选，旧 accept
        // generation 与旧 Snapshot 均保持不动，防止 ACK 一个无法真实监听的 LDS 版本。
        Some(
            reconciler
                .prepare(&candidate)
                .await
                .context("prepare xDS LDS listener topology")?,
        )
    } else {
        None
    };
    // 所有 protobuf/native 校验已完成后才执行唯一 publish；版本随后推进。ADS ACK 在本函数
    // 返回之后发送，management server 不会看到“已 ACK 但数据面仍是旧 generation”的半完成态。
    runtime
        .config_history
        .with_stable_local_files(|| -> Result<()> {
            anyhow::ensure!(
                runtime.snap.load().version == current.version,
                "xDS base snapshot changed before publication"
            );
            runtime
                .config_history
                .prepare_external_publication(&candidate)?;
            runtime.snap.store(Arc::new(candidate));
            Ok(())
        })?;
    runtime.version.store(next_version, Ordering::Release);
    if let Some(prepared) = prepared_listener {
        // publish 后的 commit 只启动已准备 acceptor 并停旧 generation，不含可失败 I/O；数据面
        // 请求一旦进入新 listener，读取到的必然已经是同一 LDS generation 的 Snapshot。
        prepared.commit();
    }
    Ok(())
}

/// 业务作用：统一校验多 type DiscoveryResponse 的版本、nonce 与总字节预算。
///
/// 参数说明：
/// - `response`：是完整 ADS 输入
/// - `limits`：是 bootstrap 硬预算。
///
/// 返回：控制字段与总字节合法时成功；超预算返回可分类 RESOURCE_EXHAUSTED。
fn validate_discovery_response_envelope(
    response: &DiscoveryResponse,
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<()> {
    anyhow::ensure!(
        !response.type_url.is_empty(),
        "ADS type_url cannot be empty"
    );
    anyhow::ensure!(
        !response.version_info.is_empty() && response.version_info.len() <= 256,
        "ADS version_info must be 1..=256 bytes"
    );
    anyhow::ensure!(
        !response.nonce.is_empty() && response.nonce.len() <= 256,
        "ADS nonce must be 1..=256 bytes"
    );
    if response.encoded_len() > limits.max_response_bytes {
        return Err(XdsResourceExhausted("xDS response exceeds max_response_bytes").into());
    }
    Ok(())
}

/// 业务作用：把规范 type URL 压缩成固定低基数观测键，未知 URL 不直接进入 metrics label。
///
/// 参数说明：
/// - `type_url`：是 ADS response/request 类型。
///
/// 返回：已启用资源域的固定小写标签或 unknown。
fn xds_type_label(type_url: &str) -> &'static str {
    match type_url {
        LDS_TYPE_URL => "lds",
        EDS_TYPE_URL => "eds",
        CDS_TYPE_URL => "cds",
        RDS_TYPE_URL => "rds",
        SDS_TYPE_URL => "sds",
        #[cfg(feature = "xds-client-extensions")]
        ECDS_TYPE_URL => "ecds",
        _ => "unknown",
    }
}

/// 业务作用：建立 EDS-only Delta ADS stream，以 per-resource cache/removed/TTL 驱动同一动态目录发布链。
///
/// 参数说明：
/// - `cfg`：固定订阅与 transport
/// - `specs`：固定订阅与 transport
/// - `cache`：跨重连保留 accepted payload/version
/// - `publisher`：是数据面发布与观测句柄。
/// - `status`：是数据面发布与观测句柄。
///
/// 返回：stream 关闭或传输失败时返回错误；资源错误在 stream 内 NACK 且不修改 cache/LKG。
async fn run_delta_stream(
    cfg: &XdsCfg,
    specs: &[XdsWatchSpec],
    cache: &mut DeltaResourceCache,
    publisher: XdsPublisher,
    status: Arc<XdsStatus>,
) -> Result<()> {
    let channel = connect_channel(cfg).await?;
    status.mark_syncing();
    let (request_tx, request_rx) = mpsc::channel(cfg.limits.max_apply_queue.max(1));
    let resource_names = subscribed_clusters(specs)?;
    request_tx
        .send(delta_request(
            EDS_TYPE_URL,
            resource_names.clone(),
            Vec::new(),
            cache.initial_versions(),
            Some(build_node(cfg)),
            String::new(),
            None,
        ))
        .await
        .context("queue initial Delta EDS request")?;

    let mut grpc = Grpc::new(channel)
        .max_decoding_message_size(cfg.limits.max_response_bytes)
        .max_encoding_message_size(1024 * 1024);
    grpc.ready()
        .await
        .context("Delta ADS gRPC service not ready")?;
    let request = tonic::Request::new(ReceiverStream::new(request_rx));
    let path = http::uri::PathAndQuery::from_static(ADS_DELTA_PATH);
    let codec = tonic_prost::ProstCodec::<DeltaDiscoveryRequest, DeltaDiscoveryResponse>::default();
    let mut responses = grpc
        .streaming(request, path, codec)
        .await
        .context("open ADS DeltaAggregatedResources")?
        .into_inner();

    loop {
        let response = if let Some(deadline) = cache.next_expiry() {
            tokio::select! {
                response = responses.message() => response.context("read Delta ADS response")?,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    apply_delta_eds_expiry(cache, specs, &publisher, status.as_ref(), &cfg.limits).await?;
                    continue;
                }
            }
        } else {
            responses
                .message()
                .await
                .context("read Delta ADS response")?
        };
        let Some(response) = response else {
            break;
        };
        let nonce = response.nonce.clone();
        let system_version = response.system_version_info.clone();
        let response_bytes = response.encoded_len();
        status.mark_received();
        let current = cache.clone();
        let translate_specs = specs.to_vec();
        let limits = cfg.limits.clone();
        status.apply_queue_depth.store(1, Ordering::Release);
        let translated_task = tokio::task::spawn_blocking(move || {
            validate_delta_response_envelope(&response, EDS_TYPE_URL, &limits)?;
            let subscribed = translate_specs
                .iter()
                .map(|spec| spec.cluster_name.clone())
                .collect::<BTreeSet<_>>();
            let response = filter_delta_named_response(&response, &subscribed);
            let (next, _) =
                current.apply_response(&response, EDS_TYPE_URL, &limits, Instant::now())?;
            validate_delta_eds_names(&response, &translate_specs, &limits)?;
            let replacement = translate_eds_resource_set(
                &next.resource_values(),
                &translate_specs,
                &limits,
                true,
            )?;
            Ok::<_, anyhow::Error>((next, replacement))
        })
        .await;
        status.apply_queue_depth.store(0, Ordering::Release);
        let translated = translated_task.context("join Delta EDS translation task")?;
        // 重复内容与 warming ACK 同样需要当前批次权威；它们不能绕过没有实际写入的发布分支。
        anyhow::ensure!(publisher.is_current(), "EDS publication authority changed");
        match translated {
            Ok((next, replacement)) => {
                let missing = delta_eds_missing(&next, specs);
                if missing.is_empty() {
                    let fingerprint = replacement_fingerprint(&replacement);
                    if status.content_unchanged(&fingerprint) {
                        status.mark_duplicate(&system_version, &nonce, next.resources.len());
                    } else {
                        // Delta cache/translation 已全部成功后才执行唯一 RCU publish；cache 与 ACK
                        // 随后推进，坏 response 不可能留下“版本已记住但数据面未应用”的半状态。
                        anyhow::ensure!(
                            publisher.publish(replacement),
                            "EDS publication authority changed"
                        );
                        status.mark_accepted(
                            &system_version,
                            &nonce,
                            next.resources.len(),
                            fingerprint,
                        );
                    }
                } else {
                    status.mark_policy_accepted(
                        EDS_TYPE_URL,
                        &system_version,
                        &nonce,
                        None,
                        None,
                        Some(&missing),
                    );
                }
                *cache = next;
                request_tx
                    .send(delta_request(
                        EDS_TYPE_URL,
                        Vec::new(),
                        Vec::new(),
                        HashMap::new(),
                        None,
                        nonce,
                        None,
                    ))
                    .await
                    .context("queue Delta EDS ACK")?;
            }
            Err(error) => {
                let code = if error.downcast_ref::<XdsResourceExhausted>().is_some() {
                    RESOURCE_EXHAUSTED_CODE
                } else {
                    INVALID_ARGUMENT_CODE
                };
                let message = truncate_error(&format!("{error:#}"));
                tracing::warn!(nonce = %nonce, error = %message, "xDS Delta EDS response NACK");
                status.mark_rejected(&nonce, &message, response_bytes);
                request_tx
                    .send(delta_request(
                        EDS_TYPE_URL,
                        Vec::new(),
                        Vec::new(),
                        HashMap::new(),
                        None,
                        nonce,
                        Some(RpcStatus {
                            code,
                            message,
                            details: Vec::new(),
                        }),
                    ))
                    .await
                    .context("queue Delta EDS NACK")?;
            }
        }
    }
    bail!("Delta ADS server closed response stream")
}

/// 业务作用：构造 Delta initial/subscription/ACK/NACK 共用 request，避免字段组合在调用点漂移。
///
/// 参数说明：
/// - `type_url`：本次请求的 xDS 资源类型 URL。
/// - `subscribe`：新增订阅的精确资源名称。
/// - `unsubscribe`：撤销订阅的精确资源名称。
/// - `initial_versions`：初始请求携带的已持有资源版本。
/// - `node`：仅初始请求携带的节点身份。
/// - `response_nonce`：需要 ACK/NACK 的响应 nonce。
/// - `error_detail`：拒绝响应时携带的结构化原因。
///
/// 返回：字段已按调用方意图填充的选择性 request。
#[allow(clippy::too_many_arguments)]
fn delta_request(
    type_url: &str,
    subscribe: Vec<String>,
    unsubscribe: Vec<String>,
    initial_versions: HashMap<String, String>,
    node: Option<Node>,
    response_nonce: String,
    error_detail: Option<RpcStatus>,
) -> DeltaDiscoveryRequest {
    DeltaDiscoveryRequest {
        node,
        type_url: type_url.to_owned(),
        resource_names_subscribe: subscribe,
        resource_names_unsubscribe: unsubscribe,
        initial_resource_versions: initial_versions,
        response_nonce,
        error_detail,
    }
}

/// 业务作用：按 named subscription 静默丢弃控制面附带的未请求资源，既遵守 Delta 协议又不越权写本地 owner 域。
///
/// 参数说明：
/// - `response`：已通过原始总字节/控制字段预算
/// - `subscribed`：是当前显式订阅集合。
///
/// 返回：保留原 nonce/system version、仅含已订阅 wrapper/removal 的 response；ACK 仍对应原始 nonce。
fn filter_delta_named_response(
    response: &DeltaDiscoveryResponse,
    subscribed: &BTreeSet<String>,
) -> DeltaDiscoveryResponse {
    DeltaDiscoveryResponse {
        system_version_info: response.system_version_info.clone(),
        resources: response
            .resources
            .iter()
            .filter(|resource| subscribed.contains(&resource.name))
            .cloned()
            .collect(),
        type_url: response.type_url.clone(),
        nonce: response.nonce.clone(),
        removed_resources: response
            .removed_resources
            .iter()
            .filter(|name| subscribed.contains(*name))
            .cloned()
            .collect(),
        control_plane: response.control_plane.clone(),
        removed_resource_names: response.removed_resource_names.clone(),
        resource_errors: response.resource_errors.clone(),
    }
}

/// 业务作用：证明 Delta wrapper.name 与 EDS ClusterLoadAssignment.cluster_name 一致，防止 version cache 键与执行资源分裂。
///
/// 参数说明：
/// - `response`：是已过 envelope/cache 门的 EDS 增量
/// - `specs`：是 owner 与预算。
/// - `limits`：是 owner 与预算。
///
/// 返回：已过滤资源的 wrapper/inner name 精确一致且可转换时成功；heartbeat/removal 不重复解码 payload。
fn validate_delta_eds_names(
    response: &DeltaDiscoveryResponse,
    specs: &[XdsWatchSpec],
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<()> {
    let subscribed = specs
        .iter()
        .map(|spec| spec.cluster_name.clone())
        .collect::<BTreeSet<_>>();
    validate_delta_named_resources(response, &subscribed, "EDS")?;
    for resource in &response.resources {
        let Some(payload) = &resource.resource else {
            continue;
        };
        validate_cluster_wire(&payload.value).context("validate Delta EDS protobuf surface")?;
        let assignment = ClusterLoadAssignment::decode(payload.value.as_slice())
            .context("decode Delta ClusterLoadAssignment")?;
        anyhow::ensure!(
            assignment.cluster_name == resource.name,
            "Delta EDS wrapper name does not match ClusterLoadAssignment.cluster_name"
        );
    }
    let payloads = response
        .resources
        .iter()
        .filter_map(|resource| resource.resource.clone())
        .collect::<Vec<_>>();
    translate_eds_resource_set(&payloads, specs, limits, false)?;
    Ok(())
}

/// 业务作用：复验 named Delta 过滤结果没有越出显式订阅域，防止调用点漏过滤后写错 owner。
///
/// 参数说明：
/// - `response`：是本轮增量
/// - `subscribed`：是本地 owner 集
/// - `resource_type`：用于有界诊断。
///
/// 返回：全部 wrapper/removal name 属于订阅时成功；调用链不变量破坏时在写 cache 前拒绝。
fn validate_delta_named_resources(
    response: &DeltaDiscoveryResponse,
    subscribed: &BTreeSet<String>,
    resource_type: &str,
) -> Result<()> {
    for name in response
        .resources
        .iter()
        .map(|resource| &resource.name)
        .chain(response.removed_resources.iter())
    {
        anyhow::ensure!(
            subscribed.contains(name),
            "unsubscribed Delta {resource_type} resource `{name}`"
        );
    }
    Ok(())
}

/// 业务作用：计算 named Delta EDS 首次同步仍未收到 upsert/remove 证据的依赖，避免把未响应误当空资源。
///
/// 参数说明：
/// - `cache`：是 accepted 增量状态
/// - `specs`：是完整订阅集合。
///
/// 返回：带 `eds:` 前缀的稳定缺失集合。
fn delta_eds_missing(cache: &DeltaResourceCache, specs: &[XdsWatchSpec]) -> BTreeSet<String> {
    specs
        .iter()
        .filter(|spec| !cache.observed.contains(&spec.cluster_name))
        .map(|spec| format!("eds:{}", spec.cluster_name))
        .collect()
}

/// 业务作用：在 Delta EDS TTL 到点时无须等待 server 消息即撤销资源并发布空 endpoint/LKG 闭包。
///
/// 参数说明：
/// - `cache`：是 accepted 状态
/// - `specs`：是 accepted 状态
/// - `publisher`：是发布点
/// - `status`：是观测
/// - `limits`：是预算。
///
/// 返回：无到期资源时无副作用；转换或发布失败返回错误使 stream 重连且旧数据面保持。
async fn apply_delta_eds_expiry(
    cache: &mut DeltaResourceCache,
    specs: &[XdsWatchSpec],
    publisher: &XdsPublisher,
    status: &XdsStatus,
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<()> {
    let mut next = cache.clone();
    let expired = next.expire_due(Instant::now(), true);
    if expired.is_empty() {
        return Ok(());
    }
    let resources = next.resource_values();
    let specs_owned = specs.to_vec();
    let limits = limits.clone();
    let replacement = tokio::task::spawn_blocking(move || {
        translate_eds_resource_set(&resources, &specs_owned, &limits, true)
    })
    .await
    .context("join Delta EDS TTL translation task")??;
    // timer 的异步转换也可能跨越配置换代，失权后不再推进旧 cache 或 warming 状态。
    anyhow::ensure!(publisher.is_current(), "EDS publication authority changed");
    let missing = delta_eds_missing(&next, specs);
    if missing.is_empty() {
        let fingerprint = replacement_fingerprint(&replacement);
        // TTL 是协议授权的 removal；完整 native 候选构建后才发布并提交 cache，不能先删版本再
        // 因转换失败留下控制面/数据面分叉。
        anyhow::ensure!(
            publisher.publish(replacement),
            "EDS publication authority changed"
        );
        status.mark_eds_ttl_applied(expired.len(), next.resources.len(), fingerprint);
    } else {
        status.mark_ttl_warming(expired.len(), &missing);
    }
    *cache = next;
    Ok(())
}

/// 业务作用：建立一代 ADS bidi stream，按 response 顺序完成 decode→validate→apply→ACK/NACK。
///
/// 参数说明：
/// - `cfg`：固定本代订阅
/// - `specs`：固定本代订阅
/// - `publisher`：接收原子 EDS 发布
/// - `status`：记录状态。
///
/// 返回：stream 持续期间不返回；连接、协议或 request queue 关闭时返回错误供外层重连。
async fn run_stream(
    cfg: &XdsCfg,
    specs: &[XdsWatchSpec],
    publisher: XdsPublisher,
    status: Arc<XdsStatus>,
) -> Result<()> {
    let channel = connect_channel(cfg).await?;
    status.mark_syncing();
    let queue = cfg.limits.max_apply_queue.max(1);
    let (request_tx, request_rx) = mpsc::channel(queue);
    let resource_names = subscribed_clusters(specs)?;
    request_tx
        .send(DiscoveryRequest {
            version_info: status.accepted_version(),
            node: Some(build_node(cfg)),
            resource_names: resource_names.clone(),
            type_url: EDS_TYPE_URL.to_owned(),
            response_nonce: String::new(),
            error_detail: None,
        })
        .await
        .context("queue initial EDS DiscoveryRequest")?;

    let mut grpc = Grpc::new(channel)
        .max_decoding_message_size(cfg.limits.max_response_bytes)
        .max_encoding_message_size(1024 * 1024);
    grpc.ready().await.context("ADS gRPC service not ready")?;
    let request = tonic::Request::new(ReceiverStream::new(request_rx));
    let path = http::uri::PathAndQuery::from_static(ADS_SOTW_PATH);
    let codec = tonic_prost::ProstCodec::<DiscoveryRequest, DiscoveryResponse>::default();
    let mut responses = grpc
        .streaming(request, path, codec)
        .await
        .context("open ADS StreamAggregatedResources")?
        .into_inner();

    while let Some(response) = responses.message().await.context("read ADS response")? {
        let nonce = response.nonce.clone();
        let response_type = response.type_url.clone();
        let version = response.version_info.clone();
        let response_bytes = response.encoded_len();
        let response_resources = response.resources.len();
        status.mark_received();
        let translate_specs = specs.to_vec();
        let limits = cfg.limits.clone();
        // 100k endpoint 的 wire allowlist/translate 是控制面 CPU 工作；每条 stream 仍严格串行，
        // 但放到 blocking pool，避免占住处理下游请求的 Tokio worker。等待本轮完成后才继续读
        // 下一 response，自然形成有界背压，不会为更新风暴无界 spawn task。
        status.apply_queue_depth.store(1, Ordering::Release);
        let translated_task = tokio::task::spawn_blocking(move || {
            translate_eds_response(&response, &translate_specs, &limits)
        })
        .await;
        status.apply_queue_depth.store(0, Ordering::Release);
        let translated = translated_task.context("join EDS translation task")?;
        // 无变化 response 也须有当前发布权，旧 stream 不能借去重路径继续确认已退休订阅。
        anyhow::ensure!(publisher.is_current(), "EDS publication authority changed");
        match translated {
            Ok(replacement) => {
                let fingerprint = replacement_fingerprint(&replacement);
                if status.content_unchanged(&fingerprint) {
                    // management server 可能用新 version/nonce 重发相同 SotW；仍须 ACK 控制流，
                    // 但跳过 ArcSwap 和 pool reconcile，避免更新风暴抢占数据面 CPU。
                    status.mark_duplicate(&version, &nonce, response_resources);
                } else {
                    // response 已全部解码和验证后才做唯一一次 RCU 发布；ACK 必须在发布之后，
                    // 否则 management server 会误以为 nonce 已经真实进入数据面。
                    anyhow::ensure!(
                        publisher.publish(replacement),
                        "EDS publication authority changed"
                    );
                    status.mark_accepted(&version, &nonce, response_resources, fingerprint);
                }
                request_tx
                    .send(DiscoveryRequest {
                        version_info: version,
                        node: None,
                        resource_names: resource_names.clone(),
                        type_url: response_type,
                        response_nonce: nonce,
                        error_detail: None,
                    })
                    .await
                    .context("queue EDS ACK")?;
            }
            Err(error) => {
                let code = if error.downcast_ref::<XdsResourceExhausted>().is_some() {
                    RESOURCE_EXHAUSTED_CODE
                } else {
                    INVALID_ARGUMENT_CODE
                };
                let message = truncate_error(&format!("{error:#}"));
                tracing::warn!(nonce = %nonce, error = %message, "xDS EDS response NACK");
                status.mark_rejected(&nonce, &message, response_bytes);
                // NACK 必须携带旧 LKG version 与本次 nonce；不能先清空动态目录，也不能把
                // 被拒 version 写进后续请求，否则会越过 last-known-good fencing。
                request_tx
                    .send(DiscoveryRequest {
                        version_info: status.accepted_version(),
                        node: None,
                        resource_names: resource_names.clone(),
                        type_url: if response_type.is_empty() {
                            EDS_TYPE_URL.to_owned()
                        } else {
                            response_type
                        },
                        response_nonce: nonce,
                        error_detail: Some(RpcStatus {
                            code,
                            message,
                            details: Vec::new(),
                        }),
                    })
                    .await
                    .context("queue EDS NACK")?;
            }
        }
    }
    bail!("ADS server closed response stream")
}

/// 业务作用：按 bootstrap transport 建立只支持 HTTP/2 的明文 loopback 或 mTLS channel。
///
/// 参数说明：
/// - `cfg`：已在快照构建期完成 URI、loopback 和 PEM 路径校验。
///
/// 返回：握手成功返回 channel；任何证书读取、TLS 或连接错误都在打开 ADS stream 前失败。
async fn connect_channel(cfg: &XdsCfg) -> Result<Channel> {
    let keepalive_interval =
        parse_duration(&cfg.keepalive.interval).context("parse xDS keepalive interval")?;
    let keepalive_timeout =
        parse_duration(&cfg.keepalive.timeout).context("parse xDS keepalive timeout")?;
    let mut endpoint = TonicEndpoint::from_shared(cfg.server.clone())
        .context("build xDS management endpoint")?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(keepalive_interval)
        .keep_alive_timeout(keepalive_timeout)
        .keep_alive_while_idle(true)
        .tcp_nodelay(true);
    if cfg.server.starts_with("https://") {
        let ca = crate::io::bounded_io::read_file(
            Path::new(&cfg.tls.ca.file),
            MAX_SECRET_BYTES,
            "xDS CA certificate",
        )?;
        let cert = crate::io::bounded_io::read_file(
            Path::new(&cfg.tls.cert.file),
            MAX_SECRET_BYTES,
            "xDS client certificate",
        )?;
        let key = crate::io::bounded_io::read_file(
            Path::new(&cfg.tls.key.file),
            MAX_SECRET_BYTES,
            "xDS client key",
        )?;
        let tls = ClientTlsConfig::new()
            .domain_name(cfg.tls.server_name.clone())
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key));
        endpoint = endpoint.tls_config(tls).context("configure xDS mTLS")?;
    }
    endpoint
        .connect()
        .await
        .context("connect xDS management server")
}

/// 业务作用：构造首个 DiscoveryRequest 的稳定 Node identity，只发送 bootstrap allowlist metadata。
///
/// 参数说明：
/// - `cfg`：是已校验 xDS bootstrap。
///
/// 返回：可与 Envoy v3 management server 互操作的选择性 Node message。
fn build_node(cfg: &XdsCfg) -> Node {
    let fields = cfg
        .node
        .metadata
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                Value {
                    kind: Some(prost_types::value::Kind::StringValue(value.clone())),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    Node {
        id: cfg.node.id.clone(),
        cluster: cfg.node.cluster.clone(),
        metadata: Some(Struct {
            fields,
        }),
        user_agent_name: "naway".to_owned(),
        user_agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        client_features: if cfg.transport == XdsTransportCfg::AdsDeltaV3 {
            vec!["xds.config.supports-resource-ttl".to_owned()]
        } else {
            Vec::new()
        },
    }
}

/// 业务作用：生成去重、排序稳定的 EDS 显式订阅集，并拒绝空或歧义 cluster 名。
///
/// 参数说明：
/// - `specs`：来自已编译上游目录。
///
/// 返回：物理 cluster 名列表；空订阅或一个 cluster 映射到多个逻辑服务时失败。
fn subscribed_clusters(specs: &[XdsWatchSpec]) -> Result<Vec<String>> {
    anyhow::ensure!(!specs.is_empty(), "xDS EDS subscription cannot be empty");
    let mut names = specs
        .iter()
        .map(|spec| spec.cluster_name.clone())
        .collect::<Vec<_>>();
    names.sort();
    anyhow::ensure!(
        names.windows(2).all(|pair| pair[0] != pair[1]),
        "each EDS cluster must map to exactly one logical service"
    );
    Ok(names)
}

/// 业务作用：将一份 EDS SotW response 全量校验并转换为 native 实例表，保持失败零副作用。
///
/// 参数说明：
/// - `response`：是 ADS 输入
/// - `specs`：固定所有权映射
/// - `limits`：是 bootstrap 硬预算。
///
/// 返回：所有资源合法时返回完整逻辑服务实例表；任一未知字段、越权 cluster、预算或 endpoint
/// 非法时返回错误，调用方必须 NACK 并保留旧 LKG。
fn translate_eds_response(
    response: &DiscoveryResponse,
    specs: &[XdsWatchSpec],
    limits: &crate::config::model::XdsLimitsCfg,
) -> Result<HashMap<String, Vec<UpstreamInstance>>> {
    anyhow::ensure!(response.type_url == EDS_TYPE_URL, "unexpected ADS type_url");
    anyhow::ensure!(
        !response.version_info.is_empty(),
        "EDS version_info cannot be empty"
    );
    anyhow::ensure!(
        response.version_info.len() <= 256,
        "EDS version_info exceeds 256 bytes"
    );
    anyhow::ensure!(!response.nonce.is_empty(), "EDS nonce cannot be empty");
    anyhow::ensure!(response.nonce.len() <= 256, "EDS nonce exceeds 256 bytes");
    if response.encoded_len() > limits.max_response_bytes {
        return Err(XdsResourceExhausted("EDS response exceeds max_response_bytes").into());
    }
    if response.resources.len() > limits.max_resources_per_type {
        return Err(XdsResourceExhausted("EDS response exceeds max_resources_per_type").into());
    }
    translate_eds_resource_set(&response.resources, specs, limits, true)
}

/// 业务作用：把完整 EDS Any 集转换为 native 实例表，供 SotW response 与 Delta accepted cache 共用。
///
/// 参数说明：
/// - `resources`：是当前完整 resource 集
/// - `specs`：固定 owner/transport
/// - `limits`：是预算
/// - `fill_missing`：为 true 时把已订阅但不存在的 resource 表示为空 endpoint。
///
/// 返回：按 logical service 的完整或增量实例表；未知 owner、重复资源和坏 endpoint 整份失败。
fn translate_eds_resource_set(
    resources: &[Any],
    specs: &[XdsWatchSpec],
    limits: &crate::config::model::XdsLimitsCfg,
    fill_missing: bool,
) -> Result<HashMap<String, Vec<UpstreamInstance>>> {
    if resources.len() > limits.max_resources_per_type {
        return Err(XdsResourceExhausted("EDS resources exceed max_resources_per_type").into());
    }
    let spec_by_cluster = specs
        .iter()
        .map(|spec| (spec.cluster_name.as_str(), spec))
        .collect::<HashMap<_, _>>();
    anyhow::ensure!(
        spec_by_cluster.len() == specs.len(),
        "duplicate EDS cluster ownership"
    );
    let mut seen = HashSet::with_capacity(resources.len());
    let mut replacement = HashMap::with_capacity(specs.len());
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == EDS_TYPE_URL,
            "EDS Any has mismatched type_url"
        );
        if resource.value.len() > limits.max_resource_bytes {
            return Err(XdsResourceExhausted("EDS resource exceeds max_resource_bytes").into());
        }
        validate_cluster_wire(&resource.value).context("validate EDS protobuf surface")?;
        let assignment = ClusterLoadAssignment::decode(resource.value.as_slice())
            .context("decode ClusterLoadAssignment")?;
        let spec = spec_by_cluster
            .get(assignment.cluster_name.as_str())
            .with_context(|| format!("unsubscribed EDS cluster `{}`", assignment.cluster_name))?;
        anyhow::ensure!(
            seen.insert(assignment.cluster_name.clone()),
            "duplicate EDS cluster `{}`",
            assignment.cluster_name
        );
        let instances = assignment_to_upstreams(&assignment, spec)
            .with_context(|| format!("translate EDS cluster `{}`", assignment.cluster_name))?;
        replacement.insert(spec.logical_service.clone(), instances);
    }
    if fill_missing {
        // SotW 缺失和 Delta explicit remove/TTL expiry 都投影为空 endpoint；调用方仍负责
        // 用 observed evidence 决定首次增量同步是否已经完整，不能把未响应误当作 remove。
        for spec in specs {
            replacement
                .entry(spec.logical_service.clone())
                .or_insert_with(Vec::new);
        }
    }
    Ok(replacement)
}

/// 业务作用：把一个已验证 ClusterLoadAssignment 转换成排序稳定的 native 上游实例。
///
/// 参数说明：
/// - `assignment`：只含当前允许字段
/// - `spec`：提供本地 transport/TLS/slow-start 策略。
///
/// 返回：全部 endpoint 合法时返回实例；权重溢出、未知健康态或不支持地址时拒绝整个 cluster。
fn assignment_to_upstreams(
    assignment: &ClusterLoadAssignment,
    spec: &XdsWatchSpec,
) -> Result<Vec<UpstreamInstance>> {
    let mut instances = Vec::new();
    for locality in &assignment.endpoints {
        anyhow::ensure!(
            locality.priority <= 1,
            "only EDS priorities 0 and 1 are supported"
        );
        let locality_weight = locality.load_balancing_weight.unwrap_or(1);
        anyhow::ensure!(locality_weight > 0, "EDS locality weight must be positive");
        if let Some(identity) = &locality.locality {
            validate_locality_text(&identity.region, "region")?;
            validate_locality_text(&identity.zone, "zone")?;
            validate_locality_text(&identity.sub_zone, "sub_zone")?;
        }
        let zone = locality
            .locality
            .as_ref()
            .map(|locality| locality.zone.trim())
            .filter(|zone| !zone.is_empty());
        let mut locality_sum = 0_u64;
        for lb in &locality.lb_endpoints {
            let endpoint_weight = lb.load_balancing_weight.unwrap_or(1);
            anyhow::ensure!(endpoint_weight > 0, "EDS endpoint weight must be positive");
            locality_sum = locality_sum
                .checked_add(endpoint_weight as u64)
                .context("EDS locality endpoint weight sum overflow")?;
            anyhow::ensure!(
                locality_sum <= u32::MAX as u64,
                "EDS locality endpoint weight sum exceeds uint32"
            );
            let weight = locality_weight
                .checked_mul(endpoint_weight)
                .context("EDS effective endpoint weight overflow")?;
            let endpoint = match &lb.host_identifier {
                Some(lb_endpoint::HostIdentifier::Endpoint(endpoint)) => endpoint,
                None => bail!("EDS LbEndpoint has no endpoint"),
                Some(lb_endpoint::HostIdentifier::EndpointName(_)) => {
                    bail!("EDS named endpoint references are unsupported")
                }
            };
            let address = endpoint
                .address
                .as_ref()
                .context("EDS endpoint has no address")?;
            let socket = match &address.address {
                Some(address::Address::SocketAddress(socket)) => socket,
                _ => bail!("EDS endpoint must use socket_address"),
            };
            anyhow::ensure!(socket.protocol == 0, "EDS endpoint must use TCP protocol");
            let port = match socket.port_specifier {
                Some(socket_address::PortSpecifier::PortValue(port))
                    if port > 0 && port <= 65535 =>
                {
                    port as u16
                }
                _ => bail!("EDS endpoint requires a non-zero numeric port"),
            };
            let ip = socket
                .address
                .parse::<std::net::IpAddr>()
                .with_context(|| {
                    format!("EDS endpoint `{}` must be an IP literal", socket.address)
                })?;
            let host = match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let down = match HealthStatus::try_from(lb.health_status) {
                Ok(HealthStatus::Unknown | HealthStatus::Healthy | HealthStatus::Degraded) => false,
                Ok(HealthStatus::Unhealthy | HealthStatus::Draining | HealthStatus::Timeout) => {
                    true
                }
                Err(_) => bail!(
                    "EDS endpoint has unknown health_status {}",
                    lb.health_status
                ),
            };
            let mut metadata = HashMap::new();
            if let Some(zone) = zone {
                metadata.insert("zone".to_owned(), zone.to_owned());
            }
            if let Some(locality) = &locality.locality {
                if !locality.region.is_empty() {
                    metadata.insert("region".to_owned(), locality.region.clone());
                }
                if !locality.sub_zone.is_empty() {
                    metadata.insert("sub_zone".to_owned(), locality.sub_zone.clone());
                }
            }
            metadata.insert("xds.cluster".to_owned(), assignment.cluster_name.clone());
            let uri = format!("{}://{}:{}", spec.scheme, host, port);
            instances.push(UpstreamInstance::try_dynamic(
                uri,
                weight,
                down,
                locality.priority == 1,
                spec.slow_start_ms,
                spec.protocol,
                spec.connect_timeout_ms,
                spec.tls_profile.clone(),
                metadata,
            )?);
        }
    }
    instances.sort_by(|left, right| left.health_key.cmp(&right.health_key));
    anyhow::ensure!(
        instances
            .windows(2)
            .all(|pair| pair[0].health_key != pair[1].health_key),
        "EDS cluster contains duplicate endpoint identity"
    );
    Ok(instances)
}

/// 业务作用：约束会进入 native metadata/locality 选择的 EDS 标识，防止大值和控制字符扩散。
///
/// 参数说明：
/// - `value`：是 region/zone/sub_zone
/// - `field`：用于定位 NACK。
///
/// 返回：空值或最多 128 bytes 的安全 ASCII 成功；其它值拒绝整份 response。
fn validate_locality_text(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(value.len() <= 128, "EDS locality {field} exceeds 128 bytes");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "EDS locality {field} contains unsupported characters"
    );
    Ok(())
}

/// 业务作用：为转换后的 native EDS 内容生成与 version/nonce/资源顺序无关的稳定摘要。
///
/// 参数说明：
/// - `replacement`：是已全量校验、即将发布的逻辑服务实例表。
///
/// 返回：按 service、health identity 和 metadata 排序的 SHA-256；只用于跳过重复 apply，不作认证。
fn replacement_fingerprint(replacement: &HashMap<String, Vec<UpstreamInstance>>) -> [u8; 32] {
    let mut services = replacement.iter().collect::<Vec<_>>();
    services.sort_by(|left, right| left.0.cmp(right.0));
    let mut digest = Sha256::new();
    for (service, instances) in services {
        hash_fingerprint_text(&mut digest, service);
        let mut instances = instances.iter().collect::<Vec<_>>();
        instances.sort_by(|left, right| left.health_key.cmp(&right.health_key));
        digest.update((instances.len() as u64).to_le_bytes());
        for instance in instances {
            hash_fingerprint_text(&mut digest, &instance.health_key);
            digest.update(instance.weight.to_le_bytes());
            digest.update(instance.connect_timeout_ms.to_le_bytes());
            digest.update([
                u8::from(instance.healthy),
                u8::from(instance.down),
                u8::from(instance.backup),
            ]);
            let mut metadata = instance.metadata.iter().collect::<Vec<_>>();
            metadata.sort_by(|left, right| left.0.cmp(right.0));
            digest.update((metadata.len() as u64).to_le_bytes());
            for (key, value) in metadata {
                hash_fingerprint_text(&mut digest, key);
                hash_fingerprint_text(&mut digest, value);
            }
        }
    }
    digest.finalize().into()
}

/// 业务作用：为已发布 CDS/RDS/EDS 闭包生成跨 type 的稳定 native 内容指纹，供节点收敛与 config-dump 对照。
///
/// 参数说明：
/// - `policy`：是 active CDS/RDS
/// - `endpoints`：是同一原子 generation 的 native 实例表。
///
/// 返回：与 management version/nonce 和内部 generation 无关的 SHA-256；只作观测，不作认证。
fn policy_fingerprint(
    policy: &XdsPolicySnapshot,
    endpoints: &HashMap<String, Vec<UpstreamInstance>>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((policy.listeners.len() as u64).to_le_bytes());
    for listener in policy.listeners.values() {
        hash_fingerprint_text(&mut digest, &listener.name);
        hash_fingerprint_text(&mut digest, &listener.listen);
        hash_fingerprint_text(&mut digest, &listener.route_name);
        #[cfg(feature = "xds-client-extensions")]
        if let Some(name) = &listener.extension_name {
            hash_fingerprint_text(&mut digest, "ecds");
            hash_fingerprint_text(&mut digest, name);
        }
        for server_name in &listener.server_names {
            hash_fingerprint_text(&mut digest, server_name);
        }
        if let Some(tls) = &listener.tls {
            hash_fingerprint_text(&mut digest, &tls.certificate_secret);
            if let Some(validation) = &tls.validation_secret {
                hash_fingerprint_text(&mut digest, validation);
            }
            digest.update([u8::from(tls.require_client_certificate)]);
        }
    }
    digest.update((policy.clusters.len() as u64).to_le_bytes());
    for cluster in policy.clusters.values() {
        hash_fingerprint_text(&mut digest, &cluster.name);
        hash_fingerprint_text(&mut digest, &cluster.eds_service_name);
        digest.update([match cluster.protocol {
            XdsUpstreamProtocol::H1 => 1,
            XdsUpstreamProtocol::H2c => 2,
        }]);
        digest.update([match cluster.lb_policy {
            XdsLbPolicy::RoundRobin => 1,
            XdsLbPolicy::LeastRequest => 2,
        }]);
        digest.update(cluster.connect_timeout_ms.to_le_bytes());
    }
    digest.update((policy.routes.len() as u64).to_le_bytes());
    for table in policy.routes.values() {
        hash_fingerprint_text(&mut digest, &table.name);
        digest.update((table.routes.len() as u64).to_le_bytes());
        for route in &table.routes {
            hash_fingerprint_text(&mut digest, &route.id);
            hash_fingerprint_text(&mut digest, &route.uri);
            digest.update((route.predicates.len() as u64).to_le_bytes());
            for predicate in &route.predicates {
                hash_fingerprint_text(&mut digest, predicate);
            }
            digest.update((route.filters.len() as u64).to_le_bytes());
            for filter in &route.filters {
                hash_fingerprint_text(&mut digest, filter);
            }
        }
    }
    digest.update((policy.secrets.len() as u64).to_le_bytes());
    for (name, secret) in &policy.secrets {
        hash_fingerprint_text(&mut digest, name);
        match secret {
            XdsSecretPlan::TlsCertificate {
                certificate_chain,
                private_key,
            } => {
                digest.update([1]);
                digest.update(certificate_chain.as_ref());
                digest.update(private_key.as_ref());
            }
            XdsSecretPlan::ValidationContext {
                trusted_ca,
            } => {
                digest.update([2]);
                digest.update(trusted_ca.as_ref());
            }
        }
    }
    digest.update(replacement_fingerprint(endpoints));
    digest.finalize().into()
}

/// 业务作用：把固定 32-byte 内容摘要转成稳定小写十六进制，避免 admin 输出二进制或高基数原文。
///
/// 参数说明：
/// - `fingerprint`：是 native xDS 内容 SHA-256。
///
/// 返回：长度固定为 64 的小写 ASCII 字符串。
fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in fingerprint {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// 业务作用：以长度前缀写入一个摘要文本字段，避免相邻字符串拼接产生边界碰撞。
///
/// 参数说明：
/// - `digest`：是当前 SHA-256
/// - `value`：是已校验的 service/identity/metadata 文本。
///
/// 返回：无；只推进摘要状态，不保存或输出原文。
fn hash_fingerprint_text(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
}

/// 业务作用：验证选择性 EDS protobuf 的原始 wire surface，拒绝 prost 会跳过的未知执行字段。
///
/// 参数说明：
/// - `bytes`：是单个 ClusterLoadAssignment Any value。
///
/// 返回：仅当前 EDS-only allowlist 字段且 wire type 正确时成功；未知/重复 singular 字段失败。
fn validate_cluster_wire(bytes: &[u8]) -> Result<()> {
    let mut seen_cluster = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(
                !seen_cluster,
                "duplicate ClusterLoadAssignment.cluster_name"
            );
            seen_cluster = true;
            expect_bytes(value, "ClusterLoadAssignment.cluster_name").map(|_| ())
        }
        2 => validate_locality_wire(expect_bytes(value, "ClusterLoadAssignment.endpoints")?),
        4 => bail!("ClusterLoadAssignment.policy is outside the EDS-only allowlist"),
        5 => bail!("ClusterLoadAssignment.named_endpoints is unsupported"),
        other => bail!("unknown ClusterLoadAssignment field {other}"),
    })?;
    anyhow::ensure!(
        seen_cluster,
        "ClusterLoadAssignment.cluster_name is required"
    );
    Ok(())
}

/// 业务作用：递归验证 LocalityLbEndpoints 的允许字段与嵌套 endpoint wire surface。
///
/// 参数说明：
/// - `bytes`：是一个 locality message。
///
/// 返回：只含 locality、lb_endpoints、weight、priority 时成功，其它能力一律拒绝。
fn validate_locality_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "LocalityLbEndpoints.locality")?;
            validate_locality_identity_wire(expect_bytes(value, "LocalityLbEndpoints.locality")?)
        }
        2 => validate_lb_endpoint_wire(expect_bytes(value, "LocalityLbEndpoints.lb_endpoints")?),
        3 => {
            mark_singular(
                &mut singular,
                field,
                "LocalityLbEndpoints.load_balancing_weight",
            )?;
            validate_u32_wrapper(expect_bytes(value, "locality weight")?)
        }
        5 => {
            mark_singular(&mut singular, field, "LocalityLbEndpoints.priority")?;
            expect_varint(value, "LocalityLbEndpoints.priority").map(|_| ())
        }
        7 | 8 => bail!("LocalityLbEndpoints LEDS/lb_config is unsupported"),
        9 => bail!("LocalityLbEndpoints metadata is outside the allowlist"),
        other => bail!("unknown LocalityLbEndpoints field {other}"),
    })
}

/// 业务作用：验证 locality 仅携带低敏 region/zone/sub_zone 字符串。
///
/// 参数说明：
/// - `bytes`：是 Envoy Locality message。
///
/// 返回：三个已知字符串字段无重复时成功，未知字段失败。
fn validate_locality_identity_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1..=3 => {
            mark_singular(&mut singular, field, "Locality identity")?;
            expect_bytes(value, "Locality identity").map(|_| ())
        }
        other => bail!("unknown Locality field {other}"),
    })
}

/// 业务作用：验证 LbEndpoint 只使用内联 endpoint、健康态和正权重。
///
/// 参数说明：
/// - `bytes`：是单个 LbEndpoint message。
///
/// 返回：allowlist surface 成功；named endpoint、metadata、未知或重复字段失败。
fn validate_lb_endpoint_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "LbEndpoint.endpoint")?;
            validate_endpoint_wire(expect_bytes(value, "LbEndpoint.endpoint")?)
        }
        2 => {
            mark_singular(&mut singular, field, "LbEndpoint.health_status")?;
            expect_varint(value, "LbEndpoint.health_status").map(|_| ())
        }
        3 => bail!("LbEndpoint metadata is outside the EDS-only allowlist"),
        4 => {
            mark_singular(&mut singular, field, "LbEndpoint.load_balancing_weight")?;
            validate_u32_wrapper(expect_bytes(value, "endpoint weight")?)
        }
        5 => bail!("LbEndpoint.endpoint_name is unsupported"),
        other => bail!("unknown LbEndpoint field {other}"),
    })
}

/// 业务作用：验证 Endpoint 只携带单一主地址，拒绝健康旁路与 additional address。
///
/// 参数说明：
/// - `bytes`：是 Endpoint message。
///
/// 返回：唯一 Address 合法时成功；其它执行字段或未知字段失败。
fn validate_endpoint_wire(bytes: &[u8]) -> Result<()> {
    let mut seen_address = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen_address, "duplicate Endpoint.address");
            seen_address = true;
            validate_address_wire(expect_bytes(value, "Endpoint.address")?)
        }
        2..=4 => bail!("Endpoint health/hostname/additional_addresses are unsupported"),
        other => bail!("unknown Endpoint field {other}"),
    })?;
    anyhow::ensure!(seen_address, "Endpoint.address is required");
    Ok(())
}

/// 业务作用：验证 Address oneof 只能选择 socket_address。
///
/// 参数说明：
/// - `bytes`：是 core Address message。
///
/// 返回：唯一 socket address 合法时成功；pipe/internal/未知字段失败。
fn validate_address_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate Address.socket_address");
            seen = true;
            validate_socket_wire(expect_bytes(value, "Address.socket_address")?)
        }
        2 | 3 => bail!("EDS pipe/internal addresses are unsupported"),
        other => bail!("unknown Address field {other}"),
    })?;
    anyhow::ensure!(seen, "Address.socket_address is required");
    Ok(())
}

/// 业务作用：验证 EDS socket 只使用 TCP、IP 字面量和 numeric port，不接受 resolver/namespace。
///
/// 参数说明：
/// - `bytes`：是 SocketAddress message。
///
/// 返回：protocol/address/port 的 wire 形态合法时成功；其它字段失败。
fn validate_socket_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 3 => {
            mark_singular(&mut singular, field, "SocketAddress numeric field")?;
            expect_varint(value, "SocketAddress numeric field").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "SocketAddress.address")?;
            expect_bytes(value, "SocketAddress.address").map(|_| ())
        }
        4..=7 => bail!("SocketAddress named port/resolver/compat/namespace is unsupported"),
        other => bail!("unknown SocketAddress field {other}"),
    })
}

/// 业务作用：验证 google.protobuf.UInt32Value 只含可选 value 字段。
///
/// 参数说明：
/// - `bytes`：是 wrapper message。
///
/// 返回：零或一个 varint value 时成功；重复、未知或错误 wire type 失败。
fn validate_u32_wrapper(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate UInt32Value.value");
            seen = true;
            expect_varint(value, "UInt32Value.value").map(|_| ())
        }
        other => bail!("unknown UInt32Value field {other}"),
    })
}

#[derive(Clone, Copy)]
enum WireValue<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32,
}

/// 业务作用：以零拷贝方式遍历 protobuf wire fields，为选择性 proto 提供 unknown-field 门禁。
///
/// 参数说明：
/// - `bytes`：是一个完整 message
/// - `visit`：同步验证每个 field。
///
/// 返回：完整消费且回调全部接受时成功；截断、溢出、group wire type 或回调拒绝时失败。
fn walk_fields<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u32, WireValue<'a>) -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        let key = take_varint(&mut bytes).context("decode protobuf field key")?;
        let field = u32::try_from(key >> 3).context("protobuf field number overflow")?;
        anyhow::ensure!(field > 0, "protobuf field number cannot be zero");
        let value = match key & 0x07 {
            0 => WireValue::Varint(take_varint(&mut bytes)?),
            1 => {
                take_exact(&mut bytes, 8)?;
                WireValue::Fixed64
            }
            2 => {
                let len = usize::try_from(take_varint(&mut bytes)?)
                    .context("protobuf length exceeds usize")?;
                WireValue::Bytes(take_exact(&mut bytes, len)?)
            }
            5 => {
                take_exact(&mut bytes, 4)?;
                WireValue::Fixed32
            }
            wire => bail!("unsupported protobuf wire type {wire}"),
        };
        visit(field, value)?;
    }
    Ok(())
}

/// 业务作用：从 protobuf 输入读取一个有溢出保护的 unsigned varint。
///
/// 参数说明：
/// - `bytes`：会推进到 varint 后。
///
/// 返回：合法最多十字节 varint；截断或第十字节溢出返回错误。
fn take_varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = bytes.split_first().context("truncated protobuf varint")?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            bail!("protobuf varint overflows u64");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint exceeds ten bytes")
}

/// 业务作用：从 protobuf 输入借用固定长度切片并推进游标，不复制资源 payload。
///
/// 参数说明：
/// - `bytes`：是剩余输入
/// - `len`：是 wire 声明长度。
///
/// 返回：长度足够时返回借用切片；截断时返回错误。
fn take_exact<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    anyhow::ensure!(bytes.len() >= len, "truncated protobuf field");
    let (head, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(head)
}

/// 业务作用：断言 wire value 是 length-delimited，并返回零拷贝 payload。
///
/// 参数说明：
/// - `value`：是已解出的 wire value
/// - `field`：用于安全错误定位。
///
/// 返回：bytes payload；其它 wire type 返回错误。
fn expect_bytes<'a>(value: WireValue<'a>, field: &str) -> Result<&'a [u8]> {
    match value {
        WireValue::Bytes(bytes) => Ok(bytes),
        _ => bail!("{field} has an invalid wire type"),
    }
}

/// 业务作用：断言 wire value 是 varint，防止同 field number 用不同 wire type 绕过校验。
///
/// 参数说明：
/// - `value`：是已解出的 wire value
/// - `field`：用于安全错误定位。
///
/// 返回：varint 值；其它 wire type 返回错误。
fn expect_varint(value: WireValue<'_>, field: &str) -> Result<u64> {
    match value {
        WireValue::Varint(value) => Ok(value),
        _ => bail!("{field} has an invalid wire type"),
    }
}

/// 业务作用：拒绝 protobuf singular field 重复编码，避免不同实现的 last-one-wins 歧义。
///
/// 参数说明：
/// - `seen`：是当前 message 的 field 集
/// - `field`：是编号
/// - `name`：用于错误定位。
///
/// 返回：首次出现成功；重复出现返回错误。
fn mark_singular(seen: &mut HashSet<u32>, field: u32, name: &str) -> Result<()> {
    anyhow::ensure!(seen.insert(field), "duplicate {name}");
    Ok(())
}

/// 业务作用：解析已经过 bootstrap 校验的紧凑 duration，供 transport timer 使用。
///
/// 参数说明：
/// - `raw`：使用 `ms/s/m/h` 整数语法。
///
/// 返回：成功返回非零 Duration；格式、零值或算术溢出返回 None。
fn parse_duration(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    let (number, multiplier) = raw
        .strip_suffix("ms")
        .map(|number| (number, 1_u64))
        .or_else(|| raw.strip_suffix('s').map(|number| (number, 1_000)))
        .or_else(|| raw.strip_suffix('m').map(|number| (number, 60_000)))
        .or_else(|| raw.strip_suffix('h').map(|number| (number, 3_600_000)))?;
    let millis = number.parse::<u64>().ok()?.checked_mul(multiplier)?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

/// 业务作用：给重连退避加入对称 jitter，降低大量 gateway 同时恢复时的惊群。
///
/// 参数说明：
/// - `base`：是当前指数退避
/// - `ratio`：已由 bootstrap 限定在 0..=1。
///
/// 返回：随机化后的非零时长；系统随机源失败时返回原值。
fn jittered(base: Duration, ratio: f64) -> Duration {
    if ratio <= 0.0 {
        return base;
    }
    let mut bytes = [0_u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return base;
    }
    let unit = u64::from_le_bytes(bytes) as f64 / u64::MAX as f64;
    let factor = (1.0 - ratio) + (2.0 * ratio * unit);
    Duration::from_secs_f64((base.as_secs_f64() * factor).max(0.001))
}

/// 业务作用：生成 xDS 新鲜度指标使用的低精度 Unix 秒时间戳。
///
/// 参数说明: 无。
///
/// 返回：系统时钟正常时返回 Unix 秒；时钟早于 epoch 时保守返回 0。
fn unix_timestamp_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 业务作用：限制 xDS 错误在日志/admin/NACK 中的大小，避免恶意资源制造内存与日志放大。
///
/// 参数说明：
/// - `error`：是本地验证错误，不应包含资源原文。
///
/// 返回：最多 512 bytes 且位于 UTF-8 边界的摘要。
fn truncate_error(error: &str) -> String {
    const LIMIT: usize = 512;
    if error.len() <= LIMIT {
        return error.to_owned();
    }
    let mut end = LIMIT;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

// 以下选择性消息字段号严格对齐 Envoy data-plane-api v3；未知字段由上面的 raw wire
// validator 拒绝，避免 prost 默认跳过导致“解析成功但执行语义被忽略”。

#[derive(Clone, PartialEq, Message)]
struct DiscoveryRequest {
    #[prost(string, tag = "1")]
    version_info: String,
    #[prost(message, optional, tag = "2")]
    node: Option<Node>,
    #[prost(string, repeated, tag = "3")]
    resource_names: Vec<String>,
    #[prost(string, tag = "4")]
    type_url: String,
    #[prost(string, tag = "5")]
    response_nonce: String,
    #[prost(message, optional, tag = "6")]
    error_detail: Option<RpcStatus>,
}

#[derive(Clone, PartialEq, Message)]
struct DiscoveryResponse {
    #[prost(string, tag = "1")]
    version_info: String,
    #[prost(message, repeated, tag = "2")]
    resources: Vec<Any>,
    #[prost(string, tag = "4")]
    type_url: String,
    #[prost(string, tag = "5")]
    nonce: String,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaDiscoveryRequest {
    #[prost(message, optional, tag = "1")]
    node: Option<Node>,
    #[prost(string, tag = "2")]
    type_url: String,
    #[prost(string, repeated, tag = "3")]
    resource_names_subscribe: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    resource_names_unsubscribe: Vec<String>,
    #[prost(map = "string, string", tag = "5")]
    initial_resource_versions: HashMap<String, String>,
    #[prost(string, tag = "6")]
    response_nonce: String,
    #[prost(message, optional, tag = "7")]
    error_detail: Option<RpcStatus>,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaDiscoveryResponse {
    #[prost(string, tag = "1")]
    system_version_info: String,
    #[prost(message, repeated, tag = "2")]
    resources: Vec<DeltaResource>,
    #[prost(string, tag = "4")]
    type_url: String,
    #[prost(string, tag = "5")]
    nonce: String,
    #[prost(string, repeated, tag = "6")]
    removed_resources: Vec<String>,
    #[prost(message, optional, tag = "7")]
    control_plane: Option<DeltaControlPlane>,
    #[prost(message, repeated, tag = "8")]
    removed_resource_names: Vec<DeltaResourceName>,
    #[prost(message, repeated, tag = "9")]
    resource_errors: Vec<DeltaResourceError>,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaResource {
    #[prost(string, tag = "1")]
    version: String,
    #[prost(message, optional, tag = "2")]
    resource: Option<Any>,
    #[prost(string, tag = "3")]
    name: String,
    #[prost(string, repeated, tag = "4")]
    aliases: Vec<String>,
    #[prost(message, optional, tag = "6")]
    ttl: Option<ProtoDuration>,
    #[prost(message, optional, tag = "7")]
    cache_control: Option<DeltaCacheControl>,
    #[prost(message, optional, tag = "8")]
    resource_name: Option<DeltaResourceName>,
    #[prost(message, optional, tag = "9")]
    metadata: Option<Struct>,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaCacheControl {
    #[prost(bool, tag = "1")]
    do_not_cache: bool,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaResourceName {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaResourceError {
    #[prost(message, optional, tag = "1")]
    resource_name: Option<DeltaResourceName>,
    #[prost(message, optional, tag = "2")]
    error_detail: Option<RpcStatus>,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaControlPlane {
    #[prost(string, tag = "1")]
    identifier: String,
}

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct Node {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    cluster: String,
    #[prost(message, optional, tag = "3")]
    metadata: Option<Struct>,
    #[prost(string, tag = "6")]
    user_agent_name: String,
    #[prost(string, tag = "7")]
    user_agent_version: String,
    #[prost(string, repeated, tag = "10")]
    client_features: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ClusterLoadAssignment {
    #[prost(string, tag = "1")]
    cluster_name: String,
    #[prost(message, repeated, tag = "2")]
    endpoints: Vec<LocalityLbEndpoints>,
}

#[derive(Clone, PartialEq, Message)]
struct LocalityLbEndpoints {
    #[prost(message, optional, tag = "1")]
    locality: Option<Locality>,
    #[prost(message, repeated, tag = "2")]
    lb_endpoints: Vec<LbEndpoint>,
    #[prost(message, optional, tag = "3")]
    load_balancing_weight: Option<u32>,
    #[prost(uint32, tag = "5")]
    priority: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Locality {
    #[prost(string, tag = "1")]
    region: String,
    #[prost(string, tag = "2")]
    zone: String,
    #[prost(string, tag = "3")]
    sub_zone: String,
}

#[derive(Clone, PartialEq, Message)]
struct LbEndpoint {
    #[prost(oneof = "lb_endpoint::HostIdentifier", tags = "1, 5")]
    host_identifier: Option<lb_endpoint::HostIdentifier>,
    #[prost(enumeration = "HealthStatus", tag = "2")]
    health_status: i32,
    #[prost(message, optional, tag = "4")]
    load_balancing_weight: Option<u32>,
}

mod lb_endpoint {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum HostIdentifier {
        #[prost(message, tag = "1")]
        Endpoint(super::Endpoint),
        #[prost(string, tag = "5")]
        EndpointName(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct Endpoint {
    #[prost(message, optional, tag = "1")]
    address: Option<Address>,
}

#[derive(Clone, PartialEq, Message)]
struct Address {
    #[prost(oneof = "address::Address", tags = "1")]
    address: Option<address::Address>,
}

mod address {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Address {
        #[prost(message, tag = "1")]
        SocketAddress(super::SocketAddress),
    }
}

#[derive(Clone, PartialEq, Message)]
struct SocketAddress {
    #[prost(int32, tag = "1")]
    protocol: i32,
    #[prost(string, tag = "2")]
    address: String,
    #[prost(oneof = "socket_address::PortSpecifier", tags = "3, 4")]
    port_specifier: Option<socket_address::PortSpecifier>,
}

mod socket_address {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum PortSpecifier {
        #[prost(uint32, tag = "3")]
        PortValue(u32),
        #[prost(string, tag = "4")]
        NamedPort(String),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum HealthStatus {
    Unknown = 0,
    Healthy = 1,
    Unhealthy = 2,
    Draining = 3,
    Timeout = 4,
    Degraded = 5,
}
