//! 单层 zone 配置的本区优先、加权份额与显式降级语义。

use super::validate_label as validate_zone;
use crate::config::model::UpstreamLocalityCfg;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;

/// 已校验的 zone-aware locality 与 failover 顺序。
#[derive(Clone)]
pub(super) struct Policy {
    local_zone: Arc<str>,
    failover_zones: Arc<[Arc<str>]>,
    allow_unlisted: bool,
    /// zone → 相对权重(万分比已折算为整数倍率)。未列 zone 取 `DEFAULT_ZONE_WEIGHT`。
    zone_weights: Arc<[(Arc<str>, u32)]>,
    /// 已声明为劣化的 zone:仍参与同一优先级,但份额按 `degraded_weight_percent` 打折。
    degraded_zones: Arc<[Arc<str>]>,
    /// 劣化 zone 的份额百分比(1..=100)。
    degraded_weight_percent: u32,
    /// true 表示 weighted 模式:全部已声明 zone 同级按份额分流。
    weighted: bool,
}

/// 未在 `zone_weights` 中声明时的默认 zone 权重。
const DEFAULT_ZONE_WEIGHT: u32 = 1;
/// zone 份额的定点放大倍数,使 `degraded_weight_percent` 这类百分比可被整数表达。
const ZONE_WEIGHT_SCALE: u32 = 100;

impl Policy {
    /// 业务作用：向管理读面保留单层 zone 策略的当前模式和本区声明。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前只读摘要，不将单层策略描述成 region/subzone 约束。
    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "model": "zone",
            "mode": if self.weighted {
                "weighted"
            } else {
                "failover"
            },
            "local_zone": self.local_zone.as_ref(),
            "allow_unlisted": self.allow_unlisted,
            "target_count": self.failover_zones.len() + 1,
        })
    }

    /// 业务作用：把声明式 zone 顺序编译成只读策略，在快照发布前拒绝空值、
    /// 重复 zone 和过长标识，避免数据面出现模糊 failover 顺序。
    ///
    /// 参数说明：
    /// - `cfg`：是 service 级 locality 声明
    /// - `service`：用于定位构建错误。
    ///
    /// 返回：成功时返回按 local→failover 排序的不可变策略；非法 zone 拒绝快照。
    pub(super) fn parse(cfg: &UpstreamLocalityCfg, service: &str) -> Result<Self> {
        let local_zone = validate_zone(&cfg.local_zone)
            .with_context(|| format!("service `{service}` locality.local_zone"))?;
        let mut seen = HashSet::new();
        seen.insert(local_zone.clone());
        let mut failover_zones = Vec::with_capacity(cfg.failover_zones.len());
        for raw in &cfg.failover_zones {
            let zone = validate_zone(raw)
                .with_context(|| format!("service `{service}` locality.failover_zones"))?;
            anyhow::ensure!(
                seen.insert(zone.clone()),
                "service `{service}` locality contains duplicate zone `{zone}`"
            );
            failover_zones.push(Arc::<str>::from(zone));
        }
        // zone 权重与劣化列表都必须引用已声明 zone:允许给未知 zone 配权重会让运维
        // 以为流量已经分过去,实际那个 zone 根本不在 failover 顺序里,属于静默失效。
        let known =
            |zone: &str| zone == local_zone || failover_zones.iter().any(|z| z.as_ref() == zone);
        let mut zone_weights = Vec::with_capacity(cfg.zone_weights.len());
        for (zone, weight) in &cfg.zone_weights {
            let zone = validate_zone(zone)
                .with_context(|| format!("service `{service}` locality.zone_weights"))?;
            anyhow::ensure!(
                known(&zone),
                "service `{service}` locality.zone_weights 引用了未声明的 zone `{zone}`"
            );
            anyhow::ensure!(
                (1..=10_000).contains(weight),
                "service `{service}` locality.zone_weights[{zone}] 必须在 1..=10000"
            );
            zone_weights.push((Arc::<str>::from(zone), *weight));
        }
        let mut degraded_zones = Vec::with_capacity(cfg.degraded_zones.len());
        for zone in &cfg.degraded_zones {
            let zone = validate_zone(zone)
                .with_context(|| format!("service `{service}` locality.degraded_zones"))?;
            anyhow::ensure!(
                known(&zone),
                "service `{service}` locality.degraded_zones 引用了未声明的 zone `{zone}`"
            );
            degraded_zones.push(Arc::<str>::from(zone));
        }
        let degraded_weight_percent = cfg.degraded_weight_percent.unwrap_or(20);
        anyhow::ensure!(
            (1..=100).contains(&degraded_weight_percent),
            "service `{service}` locality.degraded_weight_percent 必须在 1..=100"
        );
        let weighted = match cfg.mode.as_deref().unwrap_or("failover").trim() {
            "failover" => false,
            "weighted" => true,
            other => anyhow::bail!(
                "service `{service}` locality.mode `{other}` 仅支持 failover/weighted"
            ),
        };
        anyhow::ensure!(
            weighted || cfg.zone_weights.is_empty(),
            "service `{service}` locality.zone_weights 只在 mode=weighted 下生效,             failover 模式请改用 failover_zones 顺序表达优先级"
        );
        Ok(Self {
            local_zone: Arc::from(local_zone),
            failover_zones: failover_zones.into(),
            allow_unlisted: cfg.allow_unlisted,
            zone_weights: zone_weights.into(),
            degraded_zones: degraded_zones.into(),
            degraded_weight_percent,
            weighted,
        })
    }

    /// 业务作用：给出一个实例在加权 locality 调度中的份额倍率。
    ///
    /// 份额同时受三件事影响:显式 zone 权重、是否被声明为劣化 zone,以及该 zone 内
    /// 实际可用的实例数(由调用方按候选计数体现)。这样「容量、健康实例数与显式权重
    /// 共同决定份额」不是一句口号,而是三者相乘的结果。
    ///
    /// 参数说明：
    /// - `zone`：是实例的可信 zone。
    ///
    /// 返回：份额倍率;劣化 zone 已按百分比折算,最小为 1 避免被彻底饿死。
    pub(super) fn zone_multiplier(&self, zone: Option<&str>) -> u32 {
        let base = zone
            .and_then(|zone| {
                self.zone_weights
                    .iter()
                    .find(|(name, _)| name.as_ref() == zone)
                    .map(|(_, weight)| *weight)
            })
            .unwrap_or(DEFAULT_ZONE_WEIGHT);
        let degraded = zone
            .map(|zone| self.degraded_zones.iter().any(|name| name.as_ref() == zone))
            .unwrap_or(false);
        // 份额空间统一放大 `ZONE_WEIGHT_SCALE` 倍。**不放大就无法表达百分比**:
        // 默认权重是 1,直接乘 20% 再取整仍然得到 1,劣化 zone 与健康 zone 份额完全相同,
        // 配置看起来生效、实际毫无作用。
        let scaled = base * ZONE_WEIGHT_SCALE;
        if degraded {
            // 劣化 zone 不摘除、只降份额;至少保留 1 份,使它仍能承接少量真实请求。
            // 否则恢复后没有任何业务流量去验证,只能等主动探测,恢复会明显变慢。
            (scaled * self.degraded_weight_percent / 100).max(1)
        } else {
            scaled
        }
    }

    /// 业务作用：将实例 zone 映射为本区优先、指定跨区次之、未列最后的稳定等级。
    ///
    /// 参数说明：
    /// - `zone`：是可信配置或发现 metadata 中的实例 zone。
    ///
    /// 返回：可参与选择时返回越小越优先的 rank；未列且禁止降级时返回 None。
    pub(super) fn rank(&self, zone: Option<&str>) -> Option<usize> {
        let declared = zone == Some(self.local_zone.as_ref())
            || self
                .failover_zones
                .iter()
                .any(|candidate| zone == Some(candidate.as_ref()));
        if self.weighted {
            // weighted 模式:全部已声明 zone 同级,差异完全由份额倍率体现;
            // 未声明 zone 仍排在其后,只有 allow_unlisted 才可承接。
            if declared {
                return Some(0);
            }
            return self.allow_unlisted.then_some(1);
        }
        if zone == Some(self.local_zone.as_ref()) {
            return Some(0);
        }
        if let Some(index) = self
            .failover_zones
            .iter()
            .position(|candidate| zone == Some(candidate.as_ref()))
        {
            return Some(index + 1);
        }
        self.allow_unlisted
            .then_some(self.failover_zones.len().saturating_add(1))
    }
}
