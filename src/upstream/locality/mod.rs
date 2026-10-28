//! 可信拓扑的候选分层；所有协议与选择算法共用同一地域和优先级判定。

mod hierarchy;
mod zone;

use super::UpstreamInstance;
use crate::config::model::UpstreamLocalityCfg;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

const MAX_TARGETS: usize = 256;

#[derive(Clone)]
pub(super) struct Policy(Arc<Kind>);

enum Kind {
    Zone(zone::Policy),
    Hierarchy(hierarchy::Policy),
}

impl Policy {
    /// 业务作用：在配置发布前编译拓扑选择策略，禁止混用单层与分层语义造成隐式跨区流量。
    ///
    /// 参数说明：
    /// - `cfg`：服务声明的 locality 配置。
    /// - `service`：构建错误对应的逻辑服务。
    ///
    /// 返回：有界不可变策略；歧义、未知拓扑或无效权重拒绝整个候选。
    pub(super) fn parse(cfg: &UpstreamLocalityCfg, service: &str) -> Result<Self> {
        anyhow::ensure!(
            cfg.targets.len() <= MAX_TARGETS
                && cfg.failover_zones.len() < MAX_TARGETS
                && cfg.zone_weights.len() <= MAX_TARGETS
                && cfg.degraded_zones.len() <= MAX_TARGETS,
            "service `{service}` locality exceeds 256 topology entries"
        );
        let kind = if cfg.local_region.is_some() {
            anyhow::ensure!(
                cfg.failover_zones.is_empty()
                    && cfg.zone_weights.is_empty()
                    && cfg.degraded_zones.is_empty(),
                "service `{service}` hierarchical locality cannot mix zone-only policies"
            );
            Kind::Hierarchy(hierarchy::Policy::parse(cfg, service)?)
        } else {
            anyhow::ensure!(
                cfg.local_subzone.is_none() && cfg.targets.is_empty(),
                "service `{service}` hierarchical locality requires local_region"
            );
            Kind::Zone(zone::Policy::parse(cfg, service)?)
        };
        Ok(Self(Arc::new(kind)))
    }

    /// 业务作用：按实例可信拓扑确定允许参与的候选层，不读取客户端位置声明。
    ///
    /// 参数说明：
    /// - `instance`：静态配置或已验证发现目录中的候选实例。
    ///
    /// 返回：越小越优先的等级；未获允许的拓扑返回 None。
    pub(super) fn rank(&self, instance: &UpstreamInstance) -> Option<usize> {
        match self.0.as_ref() {
            Kind::Zone(policy) => policy.rank(instance.zone.as_deref()),
            Kind::Hierarchy(policy) => policy.rank(instance),
        }
    }

    /// 业务作用：将同一候选层的拓扑权重和显式劣化比例折算成整数份额。
    ///
    /// 参数说明：
    /// - `instance`：已经通过候选层判定的实例。
    ///
    /// 返回：不为零的份额倍率，与实例有效权重相乘，不绕过健康或优先级。
    pub(super) fn multiplier(&self, instance: &UpstreamInstance) -> u32 {
        match self.0.as_ref() {
            Kind::Zone(policy) => policy.zone_multiplier(instance.zone.as_deref()),
            Kind::Hierarchy(policy) => policy.multiplier(instance),
        }
    }

    /// 业务作用：向管理读面说明当前拓扑模型和受控降级边界，不在读操作中创建调度状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已编译策略的低频摘要，实例实际等级由同一 rank 判定提供。
    pub(super) fn summary(&self) -> serde_json::Value {
        match self.0.as_ref() {
            Kind::Zone(policy) => policy.summary(),
            Kind::Hierarchy(policy) => policy.summary(),
        }
    }
}

/// 业务作用：统一校验 region、zone、subzone 的精确匹配标识，防止空白和超长值绕过拓扑约束。
///
/// 参数说明：
/// - `raw`：来自配置或可信发现元数据的单个拓扑标签。
///
/// 返回：首尾空白已去除的非空 ASCII 标识；超出128字节或含其它字符则拒绝。
pub(super) fn validate_label(raw: &str) -> Result<String> {
    let value = raw.trim();
    anyhow::ensure!(!value.is_empty(), "locality label must not be empty");
    anyhow::ensure!(value.len() <= 128, "locality label must be <= 128 bytes");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "locality label must contain only ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(value.to_owned())
}

/// 业务作用：在目录构造时合并同一拓扑维度的可信别名，拒绝互相矛盾的来源声明。
///
/// 参数说明：
/// - `metadata`：注册中心或控制面已经验证来源的实例元数据。
/// - `names`：该维度允许使用的精确字段名，不读取其它字段作为拓扑权威。
///
/// 返回：未声明时为 None，声明一致时只保存一个共享标签，冲突或非法标签拒绝实例更新。
pub(super) fn metadata_value(
    metadata: &HashMap<String, String>,
    names: &[&str],
) -> Result<Option<Arc<str>>> {
    let mut result: Option<Arc<str>> = None;
    for name in names {
        if let Some(raw) = metadata.get(*name) {
            let value = validate_label(raw)?;
            anyhow::ensure!(
                result.as_deref().is_none_or(|previous| previous == value),
                "conflicting locality metadata aliases for {}",
                names[0]
            );
            result.get_or_insert_with(|| Arc::from(value));
        }
    }
    Ok(result)
}
