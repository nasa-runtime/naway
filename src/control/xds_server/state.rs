//! 单个 ADS 流的订阅、nonce、ACK/NACK、重连续接与 TTL 状态机。

use super::{plan::NodePlan, proto as p};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tonic::Status;

pub(crate) enum Request {
    Sotw(p::DiscoveryRequest),
    Delta(p::DeltaRequest),
}

pub(crate) enum Response {
    Sotw(p::DiscoveryResponse),
    Delta(p::DeltaResponse),
}

pub(crate) struct Packet {
    pub snapshot_version: u64,
    pub response: Response,
    pub secrets: bool,
}

/// 尚未交给传输的响应身份；仅用于撤销过期队列项，不保留资源或私钥正文。
pub(crate) struct Unsent {
    pub kind: String,
    pub nonce: String,
}

impl Packet {
    /// 业务作用：提取可撤销的发送身份，使更新合并不额外复制资源正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前类型和 nonce；撤销只能作用于仍匹配的未确认响应。
    pub(crate) fn unsent(&self) -> Unsent {
        match &self.response {
            Response::Sotw(r) => Unsent {
                kind: r.type_url.clone(),
                nonce: r.nonce.clone(),
            },
            Response::Delta(r) => Unsent {
                kind: r.type_url.clone(),
                nonce: r.nonce.clone(),
            },
        }
    }
}

#[derive(Default)]
struct Subscription {
    explicit: bool,
    names: BTreeSet<String>,
    known: BTreeMap<String, String>,
    force: BTreeSet<String>,
    dirty: bool,
    rejected: Option<u64>,
    flight: Option<Flight>,
    refreshed: Option<Instant>,
}

struct Flight {
    nonce: String,
    version: String,
    snapshot: u64,
    known: BTreeMap<String, String>,
    sent: Instant,
}

/// 订阅状态只属于当前流，nonce 不跨重连复用，也不反向写入 GatewaySnapshot。
pub(crate) struct Session {
    delta: bool,
    ttl_ms: u64,
    nonce_prefix: String,
    sequence: u64,
    subscriptions: BTreeMap<&'static str, Subscription>,
    latest_snapshot: u64,
    rate_window: Instant,
    request_count: u32,
}

impl Request {
    /// 业务作用：统一读取首请求和后续请求的节点声明；认证仍由外层 TLS 身份决定。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有 node 字段时借用其值；缺省表示继续使用本流首个已验证身份。
    pub(crate) fn node(&self) -> Option<&p::Node> {
        match self {
            Self::Sotw(r) => r.node.as_ref(),
            Self::Delta(r) => r.node.as_ref(),
        }
    }
}

impl Session {
    /// 业务作用：丢弃尚未进入传输的过期响应，使下一次生成直接使用最新快照而不等待不存在的 ACK。
    ///
    /// 参数说明：
    /// - `unsent`：出队或发送前发现失去版本权威的响应身份。
    ///
    /// 返回：仅撤销匹配 flight 并标记重新生成；已确认内容和其它类型的状态不受影响。
    pub(crate) fn discard(&mut self, unsent: Unsent) {
        if let Some(state) = self.subscriptions.get_mut(unsent.kind.as_str()) {
            if state
                .flight
                .as_ref()
                .is_some_and(|f| f.nonce == unsent.nonce)
            {
                state.flight = None;
                state.dirty = true;
                // 重订阅要求正文，即使被丢弃的响应只改变兴趣而未改变资源版本，也不能退化成空增量。
                state.force = state.names.clone();
            }
        }
    }

    /// 业务作用：创建协议能力已经协商的有界流状态，TTL 不会静默降级成永久资源。
    ///
    /// 参数说明：
    /// - `delta`：当前 RPC 是否为增量 ADS。
    /// - `ttl_ms`：已发布配置的资源保留期。
    /// - `node`：首请求的能力声明，不参与身份认证。
    ///
    /// 返回：能力齐全时返回空订阅状态；缺少 TTL/wrapper 能力或熵源不可用时拒绝流。
    pub(crate) fn new(delta: bool, ttl_ms: u64, node: &p::Node) -> Result<Self, Status> {
        if ttl_ms != 0
            && (!node
                .client_features
                .iter()
                .any(|f| f == "xds.config.supports-resource-ttl")
                || (!delta
                    && !node
                        .client_features
                        .iter()
                        .any(|f| f == "xds.config.supports-resource-in-sotw")))
        {
            return Err(Status::failed_precondition(
                "configured TTL requires explicit xDS client capabilities",
            ));
        }
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| Status::internal("nonce entropy unavailable"))?;
        let nonce_prefix = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            delta,
            ttl_ms,
            nonce_prefix,
            sequence: 0,
            subscriptions: BTreeMap::new(),
            latest_snapshot: 0,
            rate_window: Instant::now(),
            request_count: 0,
        })
    }

    /// 业务作用：验证订阅和 ACK/NACK，并原子更新当前类型的兴趣集合，不允许未授权名称进入常驻表。
    ///
    /// 参数说明：
    /// - `request`：经过 gRPC 字节上限的单条请求。
    /// - `node`：当前快照再次确认的节点授权。
    ///
    /// 返回：合法请求更新流内状态；越权、超限、非法重连续接或协议混用终止流。
    pub(crate) fn apply(&mut self, request: Request, node: &NodePlan) -> Result<(), Status> {
        // 参数化资源不属于当前命名空间合同；忽略 locator 会错误地把精确订阅放大为通配订阅。
        let locators = match &request {
            Request::Sotw(r) => !r.resource_locators.is_empty(),
            Request::Delta(r) => {
                !r.resource_locators_subscribe.is_empty()
                    || !r.resource_locators_unsubscribe.is_empty()
            }
        };
        if locators {
            return Err(Status::unimplemented(
                "parameterized resource locators are not supported",
            ));
        }
        let now = Instant::now();
        if now.duration_since(self.rate_window) >= Duration::from_secs(1) {
            self.rate_window = now;
            self.request_count = 0;
        }
        self.request_count += 1;
        if self.request_count > 100 {
            return Err(Status::resource_exhausted("ADS request rate exceeded"));
        }
        let (raw_kind, nonce, error, version, subscribe, unsubscribe, initial) = match request {
            Request::Sotw(r) if !self.delta => (
                r.type_url,
                r.response_nonce,
                r.error_detail,
                Some(r.version_info),
                r.resource_names,
                Vec::new(),
                BTreeMap::new(),
            ),
            Request::Delta(r) if self.delta => (
                r.type_url,
                r.response_nonce,
                r.error_detail,
                None,
                r.resource_names_subscribe,
                r.resource_names_unsubscribe,
                r.initial_resource_versions,
            ),
            _ => return Err(Status::invalid_argument("ADS RPC mode changed")),
        };
        let kind = p::TYPES
            .into_iter()
            .find(|k| *k == raw_kind)
            .ok_or_else(|| Status::invalid_argument("unsupported xDS resource type"))?;
        node.authorize(kind, "*")?;
        if subscribe.len() + unsubscribe.len() + initial.len() > super::plan::MAX_RESOURCES
            || nonce.len() > 128
            || version.as_ref().is_some_and(|v| v.len() > 128)
        {
            return Err(Status::resource_exhausted(
                "ADS request state budget exceeded",
            ));
        }
        for name in subscribe.iter().chain(&unsubscribe).chain(initial.keys()) {
            node.authorize(kind, name)?;
        }
        if initial.values().any(|v| v.len() > 128) || initial.contains_key("*") {
            return Err(Status::invalid_argument(
                "invalid initial resource versions",
            ));
        }
        let first = !self.subscriptions.contains_key(kind);
        if !first && !initial.is_empty() {
            return Err(Status::invalid_argument(
                "initial versions are only valid on the first request per type",
            ));
        }
        let state = self.subscriptions.entry(kind).or_default();
        if first {
            state.dirty = true;
            state.known = initial;
        }
        if !nonce.is_empty() && state.flight.as_ref().is_some_and(|f| f.nonce == nonce) {
            let flight = state.flight.take().expect("matched flight remains present");
            if error.is_some() {
                // NACK 不能改变已确认内容，也不能续期被拒资源；仅新发布快照可以再次提出候选。
                state.rejected = Some(flight.snapshot);
                super::metrics::NACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                if version.as_ref().is_some_and(|v| v != &flight.version) {
                    return Err(Status::invalid_argument(
                        "SotW ACK version does not match its nonce",
                    ));
                }
                state.known = flight.known;
                // TTL 从客户端收到资源开始计时；使用更早的生成时刻，迟到 ACK 不能延长正文可用期。
                state.refreshed = Some(flight.sent);
                state.rejected = None;
                super::metrics::ACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        } else if !nonce.is_empty() {
            // 旧 nonce 只是不再拥有 ACK 权威；请求中新的合法订阅变化仍应生效。
            super::metrics::STALE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if self.delta {
            if first && subscribe.is_empty() && unsubscribe.is_empty() {
                state.names.insert("*".into());
            }
            if !subscribe.is_empty() {
                state.explicit = true;
            }
            for name in unsubscribe {
                let removed = state.names.remove(&name);
                if state.names.contains("*") && name != "*" {
                    state.force.insert(name);
                    state.dirty = true;
                } else if removed {
                    state.dirty = true;
                }
            }
            for name in subscribe {
                state.names.insert(name.clone());
                state.force.insert(name);
                state.dirty = true;
            }
        } else {
            if !subscribe.is_empty() {
                state.explicit = true;
            }
            let names = if subscribe.is_empty() && !state.explicit {
                BTreeSet::from(["*".into()])
            } else {
                subscribe.into_iter().collect()
            };
            state.dirty |= names != state.names;
            state.names = names;
        }
        if state.names.len() > super::plan::MAX_RESOURCES
            || state.force.len() > super::plan::MAX_RESOURCES
        {
            return Err(Status::resource_exhausted(
                "ADS subscription capacity exceeded",
            ));
        }
        // 客户端主动取消订阅后自行删除缓存；服务端不把这种兴趣变化伪装成资源事实删除。
        if !state.names.contains("*") {
            state.known.retain(|name, _| state.names.contains(name));
        }
        Ok(())
    }

    /// 业务作用：按最新已发布快照生成至多一个响应，更新风暴只保留当前状态，不积压历史版本。
    ///
    /// 参数说明：
    /// - `snapshot`：当前 GatewaySnapshot 的单调版本。
    /// - `node`：该版本的授权资源缓存。
    ///
    /// 返回：有差异、显式重订阅或续期需要时返回一个有界响应；等待 ACK 时不生成下一份同类响应。
    pub(crate) fn next(
        &mut self,
        snapshot: u64,
        node: &NodePlan,
    ) -> Result<Option<Packet>, Status> {
        if snapshot < self.latest_snapshot {
            return Err(Status::failed_precondition(
                "published snapshot version moved backwards",
            ));
        }
        self.latest_snapshot = snapshot;
        let now = Instant::now();
        for kind in p::TYPES {
            let Some(state) = self.subscriptions.get_mut(kind) else {
                continue;
            };
            if let Some(flight) = &state.flight {
                if now.duration_since(flight.sent) >= Duration::from_secs(5) {
                    super::metrics::SLOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(Status::deadline_exceeded(
                        "ADS acknowledgement deadline exceeded",
                    ));
                }
                continue;
            }
            if state.rejected == Some(snapshot) {
                continue;
            }
            let entries = node.resources.get(kind);
            let selected: BTreeMap<_, _> = entries
                .into_iter()
                .flat_map(|e| e.iter())
                .filter(|(name, _)| {
                    state.names.contains("*") || state.names.contains(name.as_str())
                })
                .collect();
            let known: BTreeMap<_, _> = selected
                .iter()
                .map(|(name, entry)| ((*name).clone(), entry.version.clone()))
                .collect();
            let heartbeat = self.ttl_ms != 0
                && state.refreshed.is_some_and(|t| {
                    now.duration_since(t) >= Duration::from_millis(self.ttl_ms / 3)
                });
            if !state.dirty && known == state.known && !heartbeat {
                continue;
            }
            let mut resources = Vec::new();
            let mut secrets = false;
            let expired = self.ttl_ms != 0
                && state
                    .refreshed
                    .is_some_and(|t| now.duration_since(t) >= Duration::from_millis(self.ttl_ms));
            // SotW 的普通更新必须带完整内容；只有整个集合未变的续期响应才可省略正文。
            let sotw_heartbeat = heartbeat && !state.dirty && known == state.known;
            for (name, entry) in selected {
                let unchanged = state.known.get(name) == Some(&entry.version);
                let force = state.force.contains("*") || state.force.contains(name);
                if self.delta && unchanged && !force && self.ttl_ms == 0 {
                    continue;
                }
                // TTL 响应同时续期全部订阅资源，避免局部频繁更新使其它资源一直等不到心跳。
                // 停顿超过期限后客户端可能已删除缓存，此时只能用完整正文恢复，不能再发送空心跳。
                let heartbeat_only = unchanged
                    && !force
                    && self.ttl_ms != 0
                    && !expired
                    && (self.delta || sotw_heartbeat);
                secrets |= kind == p::SDS && !heartbeat_only;
                resources.push(p::Resource {
                    name: name.clone(),
                    version: entry.version.clone(),
                    resource: (!heartbeat_only).then(|| entry.value.clone()),
                    ttl: (self.ttl_ms != 0).then(|| p::duration(self.ttl_ms)),
                });
            }
            let mut removed: BTreeSet<String> = state
                .known
                .keys()
                .filter(|name| !known.contains_key(*name))
                .cloned()
                .collect();
            if state.dirty {
                for name in state.names.iter().filter(|n| n.as_str() != "*") {
                    if !known.contains_key(name) {
                        removed.insert(name.clone());
                    }
                }
            }
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("ADS nonce sequence exhausted"))?;
            let nonce = format!("{}-{}", self.nonce_prefix, self.sequence);
            // 进程重新启动后本地代数可从初值开始；流随机域避免不同内容复用旧进程的 wire version。
            let version = format!("{snapshot}-{}", self.nonce_prefix);
            let response = if self.delta {
                Response::Delta(p::DeltaResponse {
                    system_version_info: version.clone(),
                    resources,
                    type_url: kind.into(),
                    nonce: nonce.clone(),
                    removed_resources: removed.into_iter().collect(),
                })
            } else {
                let resources = resources
                    .into_iter()
                    .filter_map(|r| {
                        if self.ttl_ms != 0 {
                            Some(p::pack(p::WRAPPED, &r))
                        } else {
                            r.resource
                        }
                    })
                    .collect();
                Response::Sotw(p::DiscoveryResponse {
                    version_info: version.clone(),
                    resources,
                    type_url: kind.into(),
                    nonce: nonce.clone(),
                })
            };
            state.dirty = false;
            state.force.clear();
            state.flight = Some(Flight {
                nonce,
                version,
                snapshot,
                known,
                sent: now,
            });
            if heartbeat {
                super::metrics::HEARTBEAT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return Ok(Some(Packet {
                snapshot_version: snapshot,
                response,
                secrets,
            }));
        }
        Ok(None)
    }
}
