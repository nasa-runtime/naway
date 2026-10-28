//! 固定字段摘要与类型化分片；网络边界之外共享同一累计样本。

use super::routes;
use super::{CHUNK, SAMPLE_BYTES};
use crate::admin::management::protocol;
use crate::admin::monitor::model::{self, Histogram, NodeState, Reading, Sample, Value};
use crate::observability::http_stream::routes::{Snapshot, MAX_ROUTES};
use nagrpc::codegen::prost::Message;
use nasa::grpc::Status;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub(in crate::admin::management) struct Candidate {
    pub node: String,
    pub session: Vec<u8>,
    pub digest: [u8; 32],
    pub at: Instant,
    pub(in crate::admin::management) sample: Sample,
    total: usize,
    route_total: usize,
    frames: usize,
}

/// 业务作用：对当前样本做无中间序列化的规范摘要，标签顺序和字段边界不能产生歧义。
///
/// 参数说明：
/// - `sample`：已经验证并按指标身份排序的当前样本。
///
/// 返回：包括全部业务字段的SHA-256，不包括传输年龄和会话令牌。
pub(in crate::admin::management) fn digest(sample: &Sample) -> [u8; 32] {
    let mut hash = Sha256::new();
    stamp(&mut hash, b"naway-current-sample");
    hash.update([sample.schema_version]);
    stamp(&mut hash, sample.boot_id.as_bytes());
    for value in [
        sample.sample_id,
        sample.sampled_at_ms,
        sample.elapsed_ms,
        sample.sampling_period_ms,
        sample.state.config_version,
    ] {
        hash.update(value.to_be_bytes());
    }
    stamp(&mut hash, sample.state.mode.as_bytes());
    hash.update([u8::from(sample.state.config_fingerprint.is_some())]);
    stamp(
        &mut hash,
        sample
            .state
            .config_fingerprint
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash.update([
        u8::from(sample.state.ready),
        u8::from(sample.state.discovery_enabled),
        u8::from(sample.state.configuration_enabled),
    ]);
    for value in [
        sample.state.proxies,
        sample.state.routes,
        sample.state.services,
        sample.readings.len(),
    ] {
        hash.update((value as u64).to_be_bytes());
    }
    for reading in &sample.readings {
        stamp(&mut hash, reading.name.as_bytes());
        hash.update((reading.labels.len() as u64).to_be_bytes());
        for (key, value) in &reading.labels {
            stamp(&mut hash, key.as_bytes());
            stamp(&mut hash, value.as_bytes());
        }
        match reading.value {
            Value::Counter {
                total,
            } => {
                hash.update([0]);
                hash.update(total.to_be_bytes());
            }
            Value::Gauge {
                current,
            } => {
                hash.update([1]);
                hash.update(current.to_bits().to_be_bytes());
            }
        }
    }
    for values in [&sample.latency.bounds_ms, &sample.latency.buckets] {
        hash.update((values.len() as u64).to_be_bytes());
        for value in values {
            hash.update(value.to_be_bytes());
        }
    }
    hash.update(sample.latency.sum_micros.to_be_bytes());
    hash.update((sample.capabilities.len() as u64).to_be_bytes());
    for (key, enabled) in &sample.capabilities {
        stamp(&mut hash, key.as_bytes());
        hash.update([u8::from(*enabled)]);
    }
    routes::digest(&mut hash, sample.route_traffic.as_ref());
    hash.finalize().into()
}

/// 业务作用：以显式长度区分字符串边界，避免不同字段拼接得到相同输入。
///
/// 参数说明：
/// - `hash`：当前样本的摘要状态。
/// - `bytes`：一个完整字符串字段。
///
/// 返回：仅更新摘要，不分配中间文档。
fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// 业务作用：在网络发送边界构造一片固定系列，首片携带完整元数据且后续片不重复它。
///
/// 参数说明：
/// - `sample`：共享当前样本。
/// - `node`：已经声明的本机管理身份。
/// - `session`：该目标签发的boot会话。
/// - `hash`：完整样本的共享摘要。
/// - `at`：采集开始时刻，用于保守年龄。
/// - `offset`：已经发送的固定系列与路由行总数。
///
/// 返回：最多64固定系列或32路由行；字段长度与接收端字节上限共同限制传输。
pub(in crate::admin::management) fn frame(
    sample: &Sample,
    node: &str,
    session: &[u8],
    hash: &[u8; 32],
    at: Instant,
    offset: usize,
) -> protocol::SampleRequest {
    let header = (offset == 0).then(|| protocol::SampleHeader {
        facts: Some(protocol::NodeFacts {
            node_id: node.into(),
            boot_id: sample.boot_id.clone(),
            mode: match sample.state.mode.as_str() {
                "admin" => protocol::Mode::Admin,
                "data" => protocol::Mode::Data,
                "sidecar" => protocol::Mode::Sidecar,
                _ => protocol::Mode::AllInOne,
            } as i32,
            ready: sample.state.ready,
            config_version: sample.state.config_version,
            config_fingerprint: sample
                .state
                .config_fingerprint
                .as_ref()
                .and_then(|value| u64::from_str_radix(value, 16).ok()),
            discovery_enabled: sample.state.discovery_enabled,
            configuration_enabled: sample.state.configuration_enabled,
            proxies: sample.state.proxies as u32,
            routes: sample.state.routes as u32,
            services: sample.state.services as u32,
        }),
        sampled_at_ms: sample.sampled_at_ms,
        elapsed_ms: sample.elapsed_ms,
        sampling_period_ms: sample.sampling_period_ms,
        age_ms: at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        total: sample.readings.len() as u32,
        route_capacity: sample.route_traffic.as_ref().map(|value| value.capacity),
        route_total: sample
            .route_traffic
            .as_ref()
            .map_or(0, |value| value.rows.len() as u32),
        bounds_ms: sample.latency.bounds_ms.clone(),
        buckets: sample.latency.buckets.clone(),
        sum_micros: sample.latency.sum_micros,
        capabilities: sample
            .capabilities
            .iter()
            .map(|(name, enabled)| protocol::MetricCapability {
                name: name.clone(),
                enabled: *enabled,
            })
            .collect(),
    });
    protocol::SampleRequest {
        node_id: node.into(),
        boot_id: sample.boot_id.clone(),
        session: session.into(),
        sample_id: sample.sample_id,
        digest: hash.to_vec(),
        offset: offset as u32,
        header,
        routes: sample
            .route_traffic
            .as_ref()
            .filter(|_| offset >= sample.readings.len())
            .map_or_else(Vec::new, |value| {
                let index = offset - sample.readings.len();
                value.rows[index..(index + routes::CHUNK).min(value.rows.len())]
                    .iter()
                    .map(routes::encode)
                    .collect()
            }),
        readings: sample.readings
            [offset.min(sample.readings.len())..(offset + CHUNK).min(sample.readings.len())]
            .iter()
            .map(|reading| protocol::MetricReading {
                name: reading.name.clone(),
                labels: reading
                    .labels
                    .iter()
                    .map(|(key, value)| protocol::MetricLabel {
                        key: key.clone(),
                        value: value.clone(),
                    })
                    .collect(),
                value: Some(match reading.value {
                    Value::Counter {
                        total,
                    } => protocol::metric_reading::Value::Counter(total),
                    Value::Gauge {
                        current,
                    } => protocol::metric_reading::Value::Gauge(current),
                }),
            })
            .collect(),
    }
}

impl Candidate {
    /// 业务作用：在预留内存后验证首片清单，只为声明上限内的当前样本建立候选。
    ///
    /// 参数说明：
    /// - `first`：传输层已限制字节数的首片。
    /// - `started`：本RPC开始等待数据的单调时刻，不能从上传完成续期。
    ///
    /// 返回：未发布候选；任何身份、字段或容量错误拒绝整个上传。
    pub(in crate::admin::management) fn new(
        mut first: protocol::SampleRequest,
        started: Instant,
    ) -> Result<Self, Status> {
        if first.encoded_len() > super::super::MAX_MESSAGE
            || first.offset != 0
            || first.sample_id == 0
            || first.session.len() != 32
        {
            return Err(Status::invalid_argument("invalid sample manifest"));
        }
        let header = first
            .header
            .take()
            .ok_or_else(|| Status::invalid_argument("sample header required"))?;
        let facts = protocol::decode(
            header
                .facts
                .ok_or_else(|| Status::invalid_argument("sample facts required"))?,
        )?;
        if facts.node_id.as_deref() != Some(&first.node_id)
            || facts.boot_id != first.boot_id
            || first.boot_id.len() > 64
            || header.total as usize > model::MAX_SERIES
            || header.route_total as usize > MAX_ROUTES
            || (header.route_capacity != Some(false) && header.route_total != 0)
            || header.bounds_ms.len() > 32
            || header.buckets.len() != header.bounds_ms.len() + 1
            || header.capabilities.len() > 64
            || !matches!(header.sampling_period_ms, 1000 | 2000 | 5000 | 10000)
            || header.age_ms > header.sampling_period_ms.saturating_mul(3)
        {
            return Err(Status::invalid_argument("invalid sample bounds"));
        }
        let mut capabilities = BTreeMap::new();
        for value in header.capabilities {
            if value.name.len() > 64 || capabilities.insert(value.name, value.enabled).is_some() {
                return Err(Status::invalid_argument("invalid sample capability"));
            }
        }
        let mut candidate = Self {
            node: first.node_id.clone(),
            session: first.session.clone(),
            digest: first
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid sample digest"))?,
            at: started
                .checked_sub(Duration::from_millis(header.age_ms))
                .ok_or_else(|| Status::out_of_range("sample age overflow"))?,
            total: header.total as usize,
            route_total: header.route_total as usize,
            frames: 0,
            sample: Sample {
                schema_version: 1,
                boot_id: facts.boot_id,
                sample_id: first.sample_id,
                sampled_at_ms: header.sampled_at_ms,
                elapsed_ms: header.elapsed_ms,
                sampling_period_ms: header.sampling_period_ms,
                state: NodeState {
                    mode: facts.mode,
                    ready: facts.ready,
                    config_version: facts.config_version,
                    config_fingerprint: facts.config_fingerprint,
                    discovery_enabled: facts.discovery_enabled,
                    configuration_enabled: facts.configuration_enabled,
                    proxies: facts.proxies,
                    routes: facts.routes,
                    services: facts.services,
                },
                readings: Vec::with_capacity(header.total as usize),
                latency: Histogram {
                    bounds_ms: header.bounds_ms,
                    buckets: header.buckets,
                    sum_micros: header.sum_micros,
                },
                capabilities,
                route_traffic: header.route_capacity.map(|capacity| Snapshot {
                    capacity,
                    rows: Vec::with_capacity(header.route_total as usize),
                }),
            },
        };
        candidate.push(first)?;
        Ok(candidate)
    }

    /// 业务作用：顺序装配同一清单，重复偏移、越界和非法系列不能扩大候选或覆盖既有内容。
    ///
    /// 参数说明：
    /// - `part`：下一片类型化消息。
    ///
    /// 返回：只追加完整合法片；错误时调用方必须丢弃整个候选。
    pub(in crate::admin::management) fn push(
        &mut self,
        part: protocol::SampleRequest,
    ) -> Result<(), Status> {
        let routes_received = self
            .sample
            .route_traffic
            .as_ref()
            .map_or(0, |value| value.rows.len());
        let readings_remaining = self.total.saturating_sub(self.sample.readings.len());
        let expected_routes = if readings_remaining == 0 {
            routes::CHUNK.min(self.route_total.saturating_sub(routes_received))
        } else {
            0
        };
        if self.frames >= 49
            || part.encoded_len() > super::super::MAX_MESSAGE
            || part.header.is_some()
            || part.node_id != self.node
            || part.boot_id != self.sample.boot_id
            || part.session != self.session
            || part.sample_id != self.sample.sample_id
            || part.digest != self.digest
            || part.offset as usize != self.sample.readings.len() + routes_received
            || part.readings.len() != CHUNK.min(readings_remaining)
            || part.routes.len() != expected_routes
            || (self.frames > 0 && readings_remaining == 0 && routes_received == self.route_total)
        {
            return Err(Status::invalid_argument("sample fragment mismatch"));
        }
        self.frames += 1;
        for value in part.readings {
            if value.name.len() > 96 || value.labels.len() > 3 {
                return Err(Status::invalid_argument("invalid sample series"));
            }
            let mut labels = BTreeMap::new();
            for label in value.labels {
                if label.key.len() > 32
                    || label.value.len() > 64
                    || labels.insert(label.key, label.value).is_some()
                {
                    return Err(Status::invalid_argument("invalid sample label"));
                }
            }
            let reading = Reading {
                name: value.name,
                labels,
                value: match value.value {
                    Some(protocol::metric_reading::Value::Counter(total)) => Value::Counter {
                        total,
                    },
                    Some(protocol::metric_reading::Value::Gauge(current))
                        if current.is_finite() =>
                    {
                        Value::Gauge {
                            current,
                        }
                    }
                    _ => return Err(Status::invalid_argument("invalid sample value")),
                },
            };
            if self
                .sample
                .readings
                .last()
                .is_some_and(|old| (&old.name, &old.labels) >= (&reading.name, &reading.labels))
            {
                return Err(Status::invalid_argument(
                    "sample series must be unique and ordered",
                ));
            }
            self.sample.readings.push(reading);
        }
        for row in part.routes {
            let row = routes::decode(row)?;
            let current = self
                .sample
                .route_traffic
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("unexpected route facts"))?;
            if current
                .rows
                .last()
                .is_some_and(|old| (&old.proxy, &old.route) >= (&row.proxy, &row.route))
            {
                return Err(Status::invalid_argument(
                    "route facts must be unique and ordered",
                ));
            }
            current.rows.push(row);
        }
        Ok(())
    }

    /// 业务作用：在EOF后检查完整性与实际持有预算，半份样本不能成为当前事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整、未过期且摘要匹配的结构化样本；失败不产生可发布对象。
    pub(in crate::admin::management) fn finish(mut self) -> Result<(Sample, usize), Status> {
        if self.sample.readings.len() != self.total
            || self
                .sample
                .route_traffic
                .as_ref()
                .map_or(0, |value| value.rows.len())
                != self.route_total
            || !model::validate(&mut self.sample)
            || digest(&self.sample) != self.digest
        {
            return Err(Status::data_loss("incomplete or inconsistent sample"));
        }
        if self.at.elapsed() > Duration::from_millis(self.sample.sampling_period_ms) * 3 {
            return Err(Status::out_of_range("sample expired"));
        }
        let bytes = model::retained_bytes(&self.sample);
        if bytes > SAMPLE_BYTES {
            return Err(Status::resource_exhausted("sample memory capacity"));
        }
        Ok((self.sample, bytes))
    }
}
