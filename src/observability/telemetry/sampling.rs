//! 采样的确定性配置投影；请求只读取已验证入口、归属、产品绑定和路由身份。

mod request;
pub(super) use request::{RequestSampling, SamplingIds, ScopedSampler};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::config::model::GatewayConfig;
use crate::config::telemetry::{RemoteParent, SamplingRule, SamplingScope};
use crate::control::ownership::OwnershipCatalog;

/// 一次请求冻结的最终采样参数；不保存任意用户属性。
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Policy {
    pub head_ratio: f64,
    pub error_ratio: f64,
    pub slow_ms: u64,
    pub slow_ratio: f64,
    pub remote_parent: RemoteParent,
}

impl Policy {
    /// 业务作用：构造平台缺省决策，root head 比例沿用现有配置键。
    ///
    /// 参数说明：
    /// - `cfg`：是经过采样概率门禁的遥测声明。
    ///
    /// 返回：有限标量策略；未声明三信号时错误和慢请求提升均关闭。
    pub fn platform(cfg: &crate::config::model::TelemetryCfg) -> Self {
        let sampling = cfg.multi_signal.as_ref().map(|multi| &multi.sampling);
        Self {
            head_ratio: cfg.sample_ratio,
            error_ratio: sampling.map_or(0.0, |p| p.error_ratio),
            slow_ms: sampling.map_or(0, |p| p.slow_ms),
            slow_ratio: sampling.map_or(0.0, |p| p.slow_ratio),
            remote_parent: sampling.map_or(RemoteParent::Inherit, |p| p.remote_parent),
        }
    }

    /// 业务作用：在固定层级顺序中覆盖显式字段，未声明字段继承上层。
    ///
    /// 参数说明：
    /// - `rule`：是已验证且作用域匹配的单条声明。
    ///
    /// 返回：更新标量策略，不依赖 HashMap 或配置列表遍历顺序。
    fn overlay(&mut self, rule: &SamplingRule) {
        if let Some(value) = rule.head_ratio {
            self.head_ratio = value;
        }
        if let Some(value) = rule.error_ratio {
            self.error_ratio = value;
        }
        if let Some(value) = rule.slow_ms {
            self.slow_ms = value;
        }
        if let Some(value) = rule.slow_ratio {
            self.slow_ratio = value;
        }
        if let Some(value) = rule.remote_parent {
            self.remote_parent = value;
        }
    }
}

/// 已冻结的入口与最终路由投影；任何配置换代都重新执行引用验证。
pub(crate) struct SamplingCatalog {
    platform: Policy,
    listeners: BTreeMap<String, Policy>,
    routes: BTreeMap<String, BTreeMap<String, Policy>>,
}

impl SamplingCatalog {
    /// 业务作用：把平台→入口→workspace→product→route 规则编译为不含请求输入的固定决策。
    ///
    /// 参数说明：
    /// - `cfg`：包含已经物化的路由与产品绑定
    /// - `ownership`：是候选的完整归属图。
    ///
    /// 返回：所有作用域存在且组合有界时成功；重复、悬空引用或超预算时整轮拒绝。
    pub fn build(cfg: &GatewayConfig, ownership: &OwnershipCatalog) -> anyhow::Result<Arc<Self>> {
        let platform = Policy::platform(&cfg.telemetry);
        let mut result = Self {
            platform,
            listeners: BTreeMap::new(),
            routes: BTreeMap::new(),
        };
        let Some(multi) = &cfg.telemetry.multi_signal else {
            return Ok(Arc::new(result));
        };
        crate::config::telemetry::validate_sampling(&multi.sampling)?;
        let mut rules: Vec<_> = multi.sampling.rules.iter().collect();
        rules.sort_by_key(|rule| rank(&rule.scope));
        let route_count = if cfg.proxies.is_empty() {
            cfg.routes.len()
        } else {
            cfg.proxies.iter().map(|proxy| proxy.routes.len()).sum()
        };
        anyhow::ensure!(
            route_count <= 16_384,
            "telemetry sampling route projection exceeds capacity"
        );
        let routes: Vec<(&str, &crate::config::model::RouteCfg)> = if cfg.proxies.is_empty() {
            cfg.routes.iter().map(|route| ("default", route)).collect()
        } else {
            cfg.proxies
                .iter()
                .flat_map(|proxy| {
                    proxy
                        .routes
                        .iter()
                        .map(move |route| (proxy.id.as_str(), route))
                })
                .collect()
        };
        anyhow::ensure!(
            routes.len() <= 16_384,
            "telemetry sampling route projection exceeds capacity"
        );
        let proxies: BTreeSet<&str> = if cfg.proxies.is_empty() {
            BTreeSet::from(["default"])
        } else {
            cfg.proxies.iter().map(|proxy| proxy.id.as_str()).collect()
        };
        for rule in &rules {
            let exists = match &rule.scope {
                SamplingScope::Listener {
                    proxy,
                } => proxies.contains(proxy.as_str()),
                SamplingScope::Workspace {
                    workspace,
                } => ownership.enabled() && cfg.ownership.workspaces.contains_key(workspace),
                SamplingScope::Product {
                    product,
                    version,
                } => cfg.developer_portal.products.iter().any(|item| {
                    &item.id == product && item.versions.iter().any(|item| &item.id == version)
                }),
                SamplingScope::Route {
                    proxy,
                    route,
                } => routes
                    .iter()
                    .any(|(name, item)| *name == proxy && &item.id == route),
            };
            // 悬空引用不能静默变成平台采样，否则撤除或改名后会漏采或扩大采集范围。
            anyhow::ensure!(
                exists,
                "telemetry sampling scope references an unknown object"
            );
        }
        for proxy in proxies {
            let mut policy = platform;
            for rule in &rules {
                if matches!(&rule.scope, SamplingScope::Listener {
                    proxy: target
                } if target == proxy)
                {
                    policy.overlay(rule);
                }
            }
            result.listeners.insert(proxy.into(), policy);
        }
        let bindings = cfg
            .developer_portal
            .management
            .as_ref()
            .map(|management| management.bindings.as_slice())
            .unwrap_or_default();
        for (proxy, route) in routes {
            let mut policy = result.listeners.get(proxy).copied().unwrap_or(platform);
            let owner = ownership.route_owner(proxy, &route.id);
            let product = bindings
                .iter()
                .find(|binding| binding.proxy == proxy && binding.route == route.id);
            for rule in &rules {
                let matches = match &rule.scope {
                    SamplingScope::Listener {
                        ..
                    } => false,
                    SamplingScope::Workspace {
                        workspace,
                    } => owner.is_some_and(|owner| &owner.workspace == workspace),
                    SamplingScope::Product {
                        product: target,
                        version,
                    } => product.is_some_and(|binding| {
                        &binding.product == target && &binding.version == version
                    }),
                    SamplingScope::Route {
                        proxy: target,
                        route: id,
                    } => target == proxy && id == &route.id,
                };
                if matches {
                    policy.overlay(rule);
                }
            }
            result
                .routes
                .entry(proxy.into())
                .or_default()
                .insert(route.id.clone(), policy);
        }
        Ok(Arc::new(result))
    }

    /// 业务作用：为真实命中的配置路由读取已编译策略，不允许请求字符串选择归属。
    ///
    /// 参数说明：
    /// - `proxy`：来自活动快照；未选中路由时只使用入口与平台缺省。
    /// - `route`：来自活动快照；未选中路由时只使用入口与平台缺省。
    ///
    /// 返回：一个可按值冻结的策略，未命中时回退到已验证入口而非其它 workspace。
    pub fn policy(&self, proxy: &str, route: Option<&str>) -> Policy {
        route
            .and_then(|route| self.routes.get(proxy)?.get(route))
            .or_else(|| self.listeners.get(proxy))
            .copied()
            .unwrap_or(self.platform)
    }
}

/// 业务作用：编码唯一覆盖顺序，声明顺序不影响采样结果。
///
/// 参数说明：
/// - `scope`：是已验证的作用域类型。
///
/// 返回：入口、workspace、product、route 的固定递增优先级。
fn rank(scope: &SamplingScope) -> u8 {
    match scope {
        SamplingScope::Listener {
            ..
        } => 1,
        SamplingScope::Workspace {
            ..
        } => 2,
        SamplingScope::Product {
            ..
        } => 3,
        SamplingScope::Route {
            ..
        } => 4,
    }
}
