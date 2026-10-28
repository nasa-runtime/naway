//! 分层拓扑按显式优先级与距离选择容量，避免跨 region 的同名 zone 混为一处。

use super::validate_label;
use crate::config::model::UpstreamLocalityCfg;
use crate::upstream::UpstreamInstance;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(PartialEq, Eq)]
struct Target {
    priority: usize,
    multiplier: u32,
}

#[derive(Default, PartialEq, Eq)]
struct Zone {
    all: Option<Target>,
    subzones: HashMap<Arc<str>, Target>,
}

type Zones = HashMap<Arc<str>, Zone>;

#[derive(PartialEq, Eq)]
pub(super) struct Policy {
    local_region: Arc<str>,
    local_zone: Arc<str>,
    local_subzone: Option<Arc<str>>,
    regions: HashMap<Arc<str>, Zones>,
    weighted: bool,
    allow_unlisted: bool,
    target_count: usize,
}

impl Policy {
    /// 业务作用：编译有界的 region/zone/subzone 查询表，保证每个实例至多匹配一条权重和优先级。
    ///
    /// 参数说明：
    /// - `cfg`：已选择分层模式的服务配置。
    /// - `service`：错误上下文中的逻辑服务名。
    ///
    /// 返回：只在控制面分配的查询表；缺少目标、重复、通配重叠或无效数值均拒绝发布。
    pub(super) fn parse(cfg: &UpstreamLocalityCfg, service: &str) -> Result<Self> {
        let local_region = validate_label(
            cfg.local_region
                .as_deref()
                .context("hierarchical locality requires local_region")?,
        )?;
        let local_zone = validate_label(&cfg.local_zone)?;
        let local_subzone = cfg
            .local_subzone
            .as_deref()
            .map(validate_label)
            .transpose()?;
        let weighted = match cfg.mode.as_deref().unwrap_or("failover").trim() {
            "failover" => false,
            "weighted" => true,
            other => anyhow::bail!("service `{service}` unsupported locality mode `{other}`"),
        };
        let degraded = cfg.degraded_weight_percent.unwrap_or(20);
        anyhow::ensure!(
            (1..=100).contains(&degraded),
            "locality degraded_weight_percent must be within 1..=100"
        );
        anyhow::ensure!(
            !cfg.targets.is_empty(),
            "hierarchical locality requires nonempty targets"
        );
        let mut regions: HashMap<Arc<str>, Zones> = HashMap::new();
        for raw in &cfg.targets {
            let region = validate_label(&raw.region)?;
            let zone = validate_label(&raw.zone)?;
            let subzone = raw.subzone.as_deref().map(validate_label).transpose()?;
            anyhow::ensure!(
                raw.priority <= 65535,
                "locality target priority must be <= 65535"
            );
            anyhow::ensure!(
                (1..=10000).contains(&raw.weight),
                "locality target weight must be within 1..=10000"
            );
            let target = Target {
                priority: raw.priority as usize,
                multiplier: raw.weight
                    * if raw.degraded {
                        degraded
                    } else {
                        100
                    },
            };
            let zone = regions
                .entry(Arc::from(region))
                .or_default()
                .entry(Arc::from(zone))
                .or_default();
            // 整个 zone 的通配声明不能与细分 subzone 叠加，否则相同实例可得到两种调度份额。
            anyhow::ensure!(
                zone.all.is_none(),
                "duplicate or overlapping locality target"
            );
            match subzone {
                None => {
                    anyhow::ensure!(
                        zone.subzones.is_empty(),
                        "overlapping locality zone and subzone targets"
                    );
                    zone.all = Some(target);
                }
                Some(subzone) => {
                    anyhow::ensure!(
                        zone.subzones.insert(Arc::from(subzone), target).is_none(),
                        "duplicate locality subzone target"
                    );
                }
            }
        }
        Ok(Self {
            local_region: Arc::from(local_region),
            local_zone: Arc::from(local_zone),
            local_subzone: local_subzone.map(Arc::from),
            regions,
            weighted,
            allow_unlisted: cfg.allow_unlisted,
            target_count: cfg.targets.len(),
        })
    }

    /// 业务作用：按可信实例三层位置借用已编译目标，查找不构造组合字符串或临时集合。
    ///
    /// 参数说明：
    /// - `instance`：来自唯一实例目录的候选。
    ///
    /// 返回：精确目标或该 zone 的显式通配目标；未声明位置不自动继承同名 zone 的权限。
    fn target(&self, instance: &UpstreamInstance) -> Option<&Target> {
        let zones = self.regions.get(instance.region.as_deref()?)?;
        let zone = zones.get(instance.zone.as_deref()?)?;
        zone.all
            .as_ref()
            .or_else(|| zone.subzones.get(instance.subzone.as_deref()?))
    }

    /// 业务作用：先按显式 priority、再按本 subzone/本 zone/本 region/其它 region 分层。
    ///
    /// 参数说明：
    /// - `instance`：已经通过实例健康与请求排除判定的候选。
    ///
    /// 返回：可用等级；weighted 模式在同 priority 内不按距离分层，未列只允许最后兜底。
    pub(super) fn rank(&self, instance: &UpstreamInstance) -> Option<usize> {
        let Some(target) = self.target(instance) else {
            // 缺失 region 不是本区证据；只有明确允许未列拓扑时才能在全部声明层之后使用。
            return self.allow_unlisted.then_some(65536 * 8);
        };
        let proximity = if self.weighted {
            0
        } else if instance.region.as_deref() != Some(self.local_region.as_ref()) {
            3
        } else if instance.zone.as_deref() != Some(self.local_zone.as_ref()) {
            2
        } else if self.local_subzone.is_some()
            && instance.subzone.as_deref() != self.local_subzone.as_deref()
        {
            1
        } else {
            0
        };
        Some(target.priority * 8 + proximity)
    }

    /// 业务作用：为同层实例提供已编译份额，使实际健康实例数与显式权重共同决定流量。
    ///
    /// 参数说明：
    /// - `instance`：通过候选分层的实例。
    ///
    /// 返回：目标的固定点倍率，显式允许的未列兜底实例使用单位权重。
    pub(super) fn multiplier(&self, instance: &UpstreamInstance) -> u32 {
        self.target(instance)
            .map_or(100, |target| target.multiplier)
    }

    /// 业务作用：提供分层策略的管理摘要，使运维能区分距离优先和同层加权两种分配语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地位置、模式与容量声明，不改变实例健康或反馈。
    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "model": "hierarchical",
            "mode": if self.weighted {
                "weighted"
            } else {
                "failover"
            },
            "local_region": self.local_region.as_ref(),
            "local_zone": self.local_zone.as_ref(),
            "local_subzone": self.local_subzone.as_deref(),
            "allow_unlisted": self.allow_unlisted,
            "target_count": self.target_count,
        })
    }
}
