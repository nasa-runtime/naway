//! 服务当前状态从同次配置与动态目录借用，不枚举地址或把配置健康当作实际探活。

use super::{ServiceSource, UpstreamInstance};
use crate::config::GatewaySnapshot;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

pub(crate) const MAX_SERVICES: usize = 512;
pub(crate) const MAX_INSTANCES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Availability {
    Available,
    Missing,
    Stale,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counts {
    pub instances: u32,
    pub configured_selectable: u32,
    pub manually_down: u32,
    pub backup: u32,
    pub active_rejected: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub service: String,
    pub workspace: String,
    pub source: String,
    pub critical: bool,
    pub active_probes: bool,
    pub availability: Availability,
    pub counts: Option<Counts>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub capacity: bool,
    pub rows: Vec<Row>,
}

impl Snapshot {
    /// 业务作用：验证有限服务事实的身份、分类与计数边界，拒绝半目录或伪造健康总数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：目录完整且字段组合合法时为 true；缺失和过期不得携带旧实例计数。
    pub(crate) fn valid(&self) -> bool {
        if self.rows.len() > MAX_SERVICES
            || (self.capacity && !self.rows.is_empty())
            || self
                .rows
                .windows(2)
                .any(|pair| pair[0].service >= pair[1].service)
        {
            return false;
        }
        let mut total = 0usize;
        for row in &self.rows {
            if [&row.service, &row.workspace].into_iter().any(|name| {
                name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
            }) || !matches!(
                row.source.as_str(),
                "static" | "nacos" | "consul" | "eureka" | "dns" | "kubernetes" | "xds"
            ) || (row.source == "static" && row.availability != Availability::Available)
            {
                return false;
            }
            match (row.availability, row.counts) {
                (Availability::Available, Some(counts)) => {
                    total = total.saturating_add(counts.instances as usize);
                    if total > MAX_INSTANCES
                        || counts.configured_selectable > counts.instances
                        || counts.manually_down > counts.instances
                        || counts.backup > counts.instances
                        || counts.active_rejected > counts.instances
                        || counts.configured_selectable + counts.manually_down > counts.instances
                    {
                        return false;
                    }
                }
                (Availability::Missing | Availability::Stale, None) => {}
                _ => return false,
            }
        }
        true
    }

    /// 业务作用：把服务身份与容器实际占用纳入共享样本内存预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定结构和字符串容量之和，不扫描实例或重新序列化。
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.rows.capacity() * std::mem::size_of::<Row>()
            + self
                .rows
                .iter()
                .map(|row| {
                    row.service.capacity() + row.workspace.capacity() + row.source.capacity()
                })
                .sum::<usize>()
    }
}

/// 业务作用：在有限扫描预算内冻结独立逻辑服务状态，所有动态服务共享同次发现表视图。
///
/// 参数说明：
/// - `snapshot`：当前活动配置及同代对象归属。
/// - `active_unhealthy`：业务选择使用的当前主动探测拒绝集合，只借用，不触发探测。
///
/// 返回：按服务身份排序的完整事实；过量或非法身份撤下整份目录，缺失与过期保持未知。
pub(crate) fn capture(
    snapshot: &GatewaySnapshot,
    active_unhealthy: &super::health::Rejections,
) -> Snapshot {
    let directory = &snapshot.upstreams;
    if directory.services.len() > MAX_SERVICES {
        return capacity();
    }
    let dynamic = directory.dynamic.services.load();
    let now = Instant::now();
    let mut rows = Vec::with_capacity(directory.services.len());
    let mut scanned = 0usize;
    for (name, service) in &directory.services {
        let (availability, instances) = match service.source {
            ServiceSource::Static => (Availability::Available, Some(service.instances.as_ref())),
            _ => match dynamic.get(name) {
                None => (Availability::Missing, None),
                Some(state) => match state.availability(
                    service.discovery_identity,
                    service.discovery_stale_ttl_ms,
                    now,
                ) {
                    super::dynamic::Availability::Missing => (Availability::Missing, None),
                    super::dynamic::Availability::Stale => (Availability::Stale, None),
                    super::dynamic::Availability::Available => {
                        (Availability::Available, Some(state.instances.as_ref()))
                    }
                },
            },
        };
        let counts = if let Some(instances) = instances {
            scanned = scanned.saturating_add(instances.len());
            if scanned > MAX_INSTANCES {
                return capacity();
            }
            Some(count(
                instances,
                active_unhealthy.service(name, directory.active_health_identity(name)),
            ))
        } else {
            None
        };
        let key = format!("service:{name}");
        let workspace = snapshot
            .ownership
            .object_owner(&key)
            .map_or("platform", |owner| owner.workspace.as_str());
        if [name.as_str(), workspace].into_iter().any(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) {
            return capacity();
        }
        rows.push(Row {
            service: name.clone(),
            workspace: workspace.into(),
            source: match service.source {
                ServiceSource::Static => "static",
                ServiceSource::Nacos => "nacos",
                ServiceSource::Consul => "consul",
                ServiceSource::Eureka => "eureka",
                ServiceSource::Dns => "dns",
                ServiceSource::Kubernetes => "kubernetes",
                ServiceSource::Xds => "xds",
            }
            .into(),
            critical: service.critical,
            active_probes: service.active_health.is_some(),
            availability,
            counts,
        });
    }
    rows.sort_unstable_by(|left, right| left.service.cmp(&right.service));
    Snapshot {
        capacity: false,
        rows,
    }
}

/// 业务作用：汇总原实例的配置标志和当前探测拒绝，避免把相互重叠的类别当作独立健康分区。
///
/// 参数说明：
/// - `instances`：已纳入扫描预算的共享实例切片。
/// - `active_unhealthy`：当前主动拒绝身份集合。
///
/// 返回：固定计数，不包含地址，不代替 locality、被动保护或请求相关的最终选择门。
fn count(instances: &[Arc<UpstreamInstance>], active_unhealthy: &HashSet<String>) -> Counts {
    let mut counts = Counts {
        instances: instances.len() as u32,
        ..Counts::default()
    };
    for instance in instances {
        counts.configured_selectable += u32::from(instance.is_selectable());
        counts.manually_down += u32::from(instance.down);
        counts.backup += u32::from(instance.backup);
        // 集合已经按当前服务和策略筛选，计数与数据面选择使用相同端点身份。
        counts.active_rejected += u32::from(
            active_unhealthy.contains(instance.uri.as_ref())
                || active_unhealthy.contains(instance.health_key.as_ref()),
        );
    }
    counts
}

/// 业务作用：容量不足时只保留明确原因，防止半份服务列表被用来判断对象不存在。
///
/// 参数说明: 无。
///
/// 返回：无旧行的容量状态，不影响业务配置与实例选择。
fn capacity() -> Snapshot {
    Snapshot {
        capacity: true,
        rows: Vec::new(),
    }
}
