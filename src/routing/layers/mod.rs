//! 有界路由层级；拓扑先验证、策略再编译，请求只能沿唯一父链前进，不能退回兄弟节点重试。

mod constraints;
pub(crate) mod context;
mod explain;
pub(crate) mod metrics;
pub(super) mod policy;

use crate::config::{
    layers::{ContextCfg, LayerCfg, MatchCfg},
    model::RouteCfg,
};
use anyhow::{ensure, Context as _, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(crate) struct Node {
    pub config: LayerCfg,
    pub chain: Arc<[Arc<str>]>,
    pub order: i32,
}

pub(crate) struct Topology {
    pub nodes: BTreeMap<String, Node>,
    pub children: BTreeMap<String, Vec<String>>,
}

pub(crate) struct Plan {
    pub topology: Topology,
    routes: BTreeMap<String, Arc<crate::routing::Route>>,
}

impl Plan {
    /// 业务作用：在终端副作用之前复验整条父链来源证据，叶子的新期限不能掩盖祖先过期。
    ///
    /// 参数说明：
    /// - `chain`：是本请求实际访问的构建期稳定链。
    ///
    /// 返回：所有节点仍在同一计划且其来源期限未到时为 true；缺失或过期立即关闭本次分派。
    pub(crate) fn fresh(&self, chain: &[Arc<str>]) -> bool {
        chain.iter().all(|id| {
            self.routes.get(id.as_ref()).is_some_and(|route| {
                #[cfg(feature = "config-providers")]
                {
                    route
                        .provider_deadline
                        .is_none_or(|deadline| std::time::Instant::now() < deadline)
                }
                #[cfg(not(feature = "config-providers"))]
                {
                    let _ = route;
                    true
                }
            })
        })
    }
    /// 业务作用：把拓扑与同代已编译策略绑定，所有可达性和安全相位校验完成后才生成执行计划。
    ///
    /// 参数说明：
    /// - `topology`：为结构校验结果
    /// - `configs`：为同一次候选的原始与编译路由。
    /// - `routes`：为同一次候选的原始与编译路由。
    ///
    /// 返回：只读计划；任一策略矛盾拒绝候选，不能发布部分层级。
    pub(super) fn build(
        topology: Topology,
        configs: &[RouteCfg],
        routes: &[Arc<crate::routing::Route>],
    ) -> Result<Self> {
        let compiled = routes
            .iter()
            .map(|route| (route.id.as_str(), route))
            .collect();
        constraints::validate(&topology, &compiled)?;
        policy::validate(
            &topology,
            &configs
                .iter()
                .map(|route| (route.id.as_str(), route))
                .collect(),
            &compiled,
        )?;
        let routes = routes
            .iter()
            .filter(|route| topology.nodes.contains_key(&route.id))
            .map(|route| (route.id.clone(), route.clone()))
            .collect();
        Ok(Self {
            topology,
            routes,
        })
    }

    /// 业务作用：仅在当前父策略完成后选择一个直接子节点，不搜索孙节点或回退已执行路径。
    ///
    /// 参数说明：
    /// - `parent`：为当前层
    /// - `parts`：是未被终端变换的公开请求
    /// - `context`：是父链冻结事实。
    ///
    /// 返回：优先级最先满足全部条件的子节点；无命中保持失败，不退回普通路由。
    pub(crate) fn select(
        &self,
        parent: &str,
        parts: &http::request::Parts,
        context: &context::Context,
    ) -> Option<Arc<crate::routing::Route>> {
        self.topology.children.get(parent)?.iter().find_map(|id| {
            let route = &self.routes[id];
            (route.predicates.iter().all(|p| p.matches(parts))
                && context.matches(&self.topology.nodes[id].config.matches))
            .then(|| route.clone())
        })
    }
}

impl Topology {
    /// 业务作用：验证单 listener 内的有限父子图，先阻止环、缺失父层、空分支与重复执行路径。
    ///
    /// 参数说明：
    /// - `routes`：为尚未编译后端的原生路由声明，身份和优先级均来自同一候选。
    ///
    /// 返回：单层配置不创建层级计划；有层级时返回固定拓扑，任何结构或变量相位矛盾拒绝整个候选。
    pub(crate) fn build(routes: &[RouteCfg]) -> Result<Option<Self>> {
        if routes.iter().all(|route| route.layer.is_none()) {
            return Ok(None);
        }
        let mut all = BTreeMap::new();
        for route in routes {
            ensure!(
                all.insert(route.id.as_str(), route).is_none(),
                "duplicate layered route identity"
            );
        }
        let declarations: BTreeMap<_, _> = routes
            .iter()
            .filter_map(|route| {
                route
                    .layer
                    .as_ref()
                    .map(|layer| (route.id.as_str(), (route, layer)))
            })
            .collect();
        ensure!(declarations.len() <= 1024, "layered route capacity reached");
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, (_, layer)) in &declarations {
            ensure!(context::name(id), "invalid layered route identity");
            validate_context(layer)?;
            if let Some(parent) = &layer.parent_ref {
                ensure!(context::name(parent), "invalid parent route identity");
                let (_, parent_cfg) = declarations
                    .get(parent.as_str())
                    .context("layer parent is absent or not layered")?;
                ensure!(parent_cfg.branch, "layer parent must be a branch");
                let siblings = children.entry(parent.clone()).or_default();
                siblings.push((*id).to_owned());
                ensure!(siblings.len() <= 64, "layer child capacity reached");
            } else {
                // 根选择发生在认证之前；不能用尚未产生的身份或风险来决定是否执行根安全策略。
                ensure!(
                    layer.matches.is_empty(),
                    "root route cannot match post-policy context"
                );
            }
        }
        let mut nodes = BTreeMap::new();
        for (id, (route, layer)) in &declarations {
            ensure!(
                !layer.branch || children.contains_key(*id),
                "layer branch has no reachable child"
            );
            let mut seen = BTreeSet::new();
            let mut chain = Vec::new();
            let mut cursor = *id;
            loop {
                ensure!(
                    seen.insert(cursor),
                    "layer cycle or repeated execution path"
                );
                chain.push(cursor);
                ensure!(chain.len() <= 8, "layer depth capacity reached");
                match declarations[cursor].1.parent_ref.as_deref() {
                    Some(parent) => cursor = parent,
                    None => break,
                }
            }
            chain.reverse();
            let mut variables: BTreeMap<&str, &ContextCfg> = BTreeMap::new();
            for ancestor in &chain {
                let declaration = declarations[ancestor].1;
                for condition in &declaration.matches {
                    if let MatchCfg::Variable {
                        name,
                        equals,
                    } = condition
                    {
                        let source = variables
                            .get(name.as_str())
                            .context("layer variable is not available from a parent")?;
                        if let ContextCfg::Literal {
                            value,
                        } = source
                        {
                            ensure!(value == equals, "layer variable condition is unreachable");
                        }
                    }
                }
                for (name, value) in &declaration.context {
                    // 匹配先于本层上下文追加；同名覆盖会改变父层已冻结授权含义，因此即使值相同也拒绝。
                    ensure!(
                        variables.insert(name.as_str(), value).is_none(),
                        "trusted layer variable assigned more than once"
                    );
                    ensure!(
                        variables.len() <= 32,
                        "trusted layer path variable capacity reached"
                    );
                }
            }
            nodes.insert(
                (*id).to_owned(),
                Node {
                    config: (*layer).clone(),
                    chain: chain.into_iter().map(Arc::from).collect::<Vec<_>>().into(),
                    order: route.order,
                },
            );
        }
        for siblings in children.values_mut() {
            siblings.sort_by(|left, right| {
                all[left.as_str()]
                    .order
                    .cmp(&all[right.as_str()].order)
                    .then_with(|| left.cmp(right))
            });
        }
        Ok(Some(Self {
            nodes,
            children,
        }))
    }

    /// 业务作用：在普通入口匹配阶段排除只能经父层进入的子路由，不能由更高书写优先级绕过认证。
    ///
    /// 参数说明：
    /// - `id`：是已编译 route 的稳定身份。
    ///
    /// 返回：节点具有显式父引用时为 true；单层路由或根节点为 false。
    pub(crate) fn is_child(&self, id: &str) -> bool {
        self.nodes
            .get(id)
            .is_some_and(|node| node.config.parent_ref.is_some())
    }
}

/// 业务作用：约束冻结条件与上下文声明的语法和容量，未知变量来源不能静默解释为客户端字段。
///
/// 参数说明：
/// - `layer`：为一个节点的强类型本地声明。
///
/// 返回：有限精确配置通过；空值、控制字符、重复条件或超限拒绝。
fn validate_context(layer: &LayerCfg) -> Result<()> {
    ensure!(
        layer.matches.len() <= 16 && layer.context.len() <= 16,
        "layer context capacity reached"
    );
    let mut unique = BTreeSet::new();
    for condition in &layer.matches {
        ensure!(
            unique.insert(serde_json::to_string(condition)?),
            "duplicate layer condition"
        );
        let valid = match condition {
            MatchCfg::Authenticated {
                ..
            }
            | MatchCfg::Risk {
                ..
            } => true,
            MatchCfg::Consumer {
                equals,
            } => context::text(equals),
            MatchCfg::Claim {
                name,
                equals,
            }
            | MatchCfg::Variable {
                name,
                equals,
            } => context::name(name) && context::text(equals),
            MatchCfg::ClaimContains {
                name,
                value,
            } => context::name(name) && context::text(value),
        };
        ensure!(valid, "invalid layer condition");
    }
    for (name, value) in &layer.context {
        ensure!(context::name(name), "invalid trusted layer variable");
        ensure!(
            match value {
                ContextCfg::Literal {
                    value,
                } => context::text(value),
                ContextCfg::Claim {
                    name,
                } => context::name(name),
            },
            "invalid trusted layer value"
        );
    }
    Ok(())
}
