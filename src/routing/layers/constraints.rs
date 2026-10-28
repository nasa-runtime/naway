//! 层级可达性与同级冲突；只接受能够确定比较的公开断言，不以正则近似证明授权路径。

use super::{Node, Topology};
use crate::config::layers::MatchCfg;
use crate::routing::{
    predicate::{HostPattern, Predicate},
    Route,
};
use anyhow::{ensure, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// 业务作用：证明每条父链的公开请求交集非空，并拒绝可能同时命中的同优先级兄弟。
///
/// 参数说明：
/// - `topology`：是已验证拓扑
/// - `routes`：为同一候选的已编译路由，不包含运行期身份值。
///
/// 返回：可确定选择的有限层级通过；不支持的断言、不可达路径或同优先级歧义拒绝。
pub(super) fn validate(topology: &Topology, routes: &BTreeMap<&str, &Arc<Route>>) -> Result<()> {
    for (id, node) in &topology.nodes {
        let route = routes[id.as_str()];
        ensure!(
            route.predicates.len() <= 8,
            "layer public predicate capacity reached"
        );
        for predicate in &route.predicates {
            let allowed = match predicate {
                Predicate::PathPrefix(value)
                | Predicate::PathElementPrefix(value)
                | Predicate::PathExact(value) => {
                    value.starts_with('/')
                        && value.len() <= 2048
                        && !value.contains(['?', '#'])
                        && !value.chars().any(char::is_control)
                }
                Predicate::Method(methods) => !methods.is_empty() && methods.len() <= 16,
                Predicate::Host(patterns) => !patterns.is_empty() && patterns.len() <= 8,
                _ => false,
            };
            ensure!(
                allowed,
                "layer public predicates require bounded literal path, host or method"
            );
        }
        let predicates: Vec<_> = node
            .chain
            .iter()
            .flat_map(|id| routes[id.as_ref()].predicates.iter())
            .collect();
        let conditions: Vec<_> = node
            .chain
            .iter()
            .flat_map(|id| topology.nodes[id.as_ref()].config.matches.iter())
            .collect();
        ensure!(
            possible(&predicates) && consistent(&conditions),
            "layer route is unreachable through its parent path"
        );
    }
    for children in topology.children.values() {
        for (index, left) in children.iter().enumerate() {
            for right in &children[index + 1..] {
                let left_node = &topology.nodes[left];
                let right_node = &topology.nodes[right];
                if left_node.order == right_node.order {
                    let public: Vec<_> = routes[left.as_str()]
                        .predicates
                        .iter()
                        .chain(routes[right.as_str()].predicates.iter())
                        .collect();
                    let context: Vec<_> = left_node
                        .config
                        .matches
                        .iter()
                        .chain(right_node.config.matches.iter())
                        .collect();
                    ensure!(
                        !possible(&public)
                            || !consistent(&context)
                            || exclusive_phase(left_node, right_node),
                        "same-priority layer children may overlap"
                    );
                } else {
                    let later_predicates: Vec<_> = right_node
                        .chain
                        .iter()
                        .flat_map(|id| routes[id.as_ref()].predicates.iter())
                        .collect();
                    let covered = covers(&routes[left.as_str()].predicates, &later_predicates)
                        && left_node
                            .config
                            .matches
                            .iter()
                            .all(|condition| right_node.config.matches.contains(condition));
                    ensure!(
                        !covered,
                        "layer child is fully shadowed by an earlier sibling"
                    );
                }
            }
        }
    }
    Ok(())
}

/// 业务作用：按实际字面量包含关系识别被先行兄弟完全遮蔽的公开请求域。
///
/// 参数说明：
/// - `earlier`：是优先节点的约束
/// - `later`：包括后行节点与共同父链的约束。
///
/// 返回：后行域的每个取值都满足先行约束时为 true；不采用字符串签名近似前缀语义。
fn covers(earlier: &[Predicate], later: &[&Predicate]) -> bool {
    earlier.iter().all(|outer| match outer {
        Predicate::Method(expected) => {
            let sets: Vec<_> = later.iter().filter_map(|p| match p {
                Predicate::Method(v)=>Some(v),_=>None
            }).collect();
            sets.first().is_some_and(|first| first.iter()
                .filter(|m| sets.iter().all(|set| set.contains(m))).all(|m| expected.contains(m)))
        }
        Predicate::Host(expected) => {
            let sets: Vec<_> = later.iter().filter_map(|p| match p {
                Predicate::Host(v)=>Some(v),_=>None
            }).collect();
            let Some(first) = sets.first() else {
                return false
            };
            let mut domain: Vec<&HostPattern> = first.iter().collect();
            for set in &sets[1..] {
                domain = domain.iter().flat_map(|left| set.iter().filter_map(move |right| {
                    if host_covers(left,right) {
                        Some(right)
                    } else if host_covers(right,left) {
                        Some(*left)
                    } else {
                        None
                    }
                })).collect();
                // 交集只保留最宽代表；每一步仍受原始有限 host 集合约束，不能产生组合爆炸。
                domain.sort_by_key(|p| match p {
                    HostPattern::Exact(s)=>(0,s.as_str()),HostPattern::Suffix(s)=>(1,s.as_str())
                });
                domain.dedup_by(|a,b| host_covers(a,b) && host_covers(b,a));
                let all=domain.clone();
                domain.retain(|p| !all.iter().any(|q| host_covers(q,p) && !host_covers(p,q)));
            }
            domain.iter().all(|inner| expected.iter().any(|outer| host_covers(outer,inner)))
        }
        _ => later.iter().any(|inner| path_covers(outer,inner))
            || matches!(outer, Predicate::PathPrefix(p)|Predicate::PathElementPrefix(p) if p=="/"),
    })
}

/// 业务作用：计算可判定路径域的包含关系，保留完整 segment 与裸前缀的区别。
///
/// 参数说明：
/// - `outer`：是拟覆盖域
/// - `inner`：是待证明的更窄域。
///
/// 返回：inner 的全部路径均属于 outer 时为 true。
fn path_covers(outer: &Predicate, inner: &Predicate) -> bool {
    match (outer, inner) {
        (
            Predicate::PathPrefix(a),
            Predicate::PathPrefix(b) | Predicate::PathElementPrefix(b) | Predicate::PathExact(b),
        ) => b.starts_with(a),
        (
            Predicate::PathElementPrefix(a),
            Predicate::PathElementPrefix(b) | Predicate::PathExact(b),
        ) => a == "/" || a == b || b.strip_prefix(a).is_some_and(|s| s.starts_with('/')),
        (Predicate::PathElementPrefix(a), Predicate::PathPrefix(b)) => {
            a == "/" || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
        }
        (Predicate::PathExact(a), Predicate::PathExact(b)) => a == b,
        _ => false,
    }
}

/// 业务作用：比较精确 Host 与点边界后缀域，禁止将兄弟域名误判为子域。
///
/// 参数说明：
/// - `outer`：为已规范化的原生 Host 模式。
/// - `inner`：为已规范化的原生 Host 模式。
///
/// 返回：inner 被 outer 完全包含时为 true。
fn host_covers(outer: &HostPattern, inner: &HostPattern) -> bool {
    match (outer, inner) {
        (HostPattern::Exact(a), HostPattern::Exact(b)) => a == b,
        (HostPattern::Suffix(a), HostPattern::Exact(b) | HostPattern::Suffix(b)) => b.ends_with(a),
        _ => false,
    }
}

/// 业务作用：对路径、Host 和方法的交集寻找有限见证，避免配置一条永远无法走到的父子链。
///
/// 参数说明：
/// - `predicates`：已限定为可决定的字面量集合，不含 regex、glob 或动态变量。
///
/// 返回：每种公开属性都有满足全部约束的取值时为 true。
fn possible(predicates: &[&Predicate]) -> bool {
    let paths: Vec<_> = predicates
        .iter()
        .filter_map(|predicate| match predicate {
            Predicate::PathPrefix(value)
            | Predicate::PathElementPrefix(value)
            | Predicate::PathExact(value) => Some(value.as_str()),
            _ => None,
        })
        .collect();
    if let Some(longest) = paths.iter().max_by_key(|value| value.len()) {
        let witnesses = [(*longest).to_owned(), format!("{longest}/")];
        if !witnesses.iter().any(|path| {
            predicates.iter().all(|predicate| match predicate {
                Predicate::PathPrefix(value) => path.starts_with(value),
                Predicate::PathElementPrefix(value) => {
                    value == "/"
                        || path == value
                        || path
                            .strip_prefix(value)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                }
                Predicate::PathExact(value) => path == value,
                _ => true,
            })
        }) {
            return false;
        }
    }
    let method_sets: Vec<_> = predicates
        .iter()
        .filter_map(|predicate| {
            if let Predicate::Method(values) = predicate {
                Some(values)
            } else {
                None
            }
        })
        .collect();
    if let Some(first) = method_sets.first() {
        if !first
            .iter()
            .any(|method| method_sets.iter().all(|values| values.contains(method)))
        {
            return false;
        }
    }
    let host_sets: Vec<_> = predicates
        .iter()
        .filter_map(|predicate| {
            if let Predicate::Host(values) = predicate {
                Some(values)
            } else {
                None
            }
        })
        .collect();
    if !host_sets.is_empty() {
        let witnesses: Vec<_> = host_sets
            .iter()
            .flat_map(|values| {
                values.iter().map(|pattern| match pattern {
                    HostPattern::Exact(value) => value.clone(),
                    HostPattern::Suffix(value) => format!("x{value}"),
                })
            })
            .collect();
        if !witnesses.iter().any(|host| {
            host_sets.iter().all(|values| {
                values.iter().any(|pattern| match pattern {
                    HostPattern::Exact(value) => host.eq_ignore_ascii_case(value),
                    HostPattern::Suffix(value) => host.ends_with(value),
                })
            })
        }) {
            return false;
        }
    }
    true
}

/// 业务作用：检测冻结身份和只写一次变量上的相互矛盾比较；数组成员与字符串相等不能混为同一 claim 类型。
///
/// 参数说明：
/// - `conditions`：为同一父链或同级交集中的受信条件。
///
/// 返回：没有确定矛盾时为 true，不把未知身份当作已满足条件。
fn consistent(conditions: &[&MatchCfg]) -> bool {
    let mut equal = BTreeMap::new();
    let mut members: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for condition in conditions {
        let pair = match condition {
            MatchCfg::Consumer {
                equals,
            } => Some(("consumer", "", equals.as_str())),
            MatchCfg::Claim {
                name,
                equals,
            } => Some(("claim", name.as_str(), equals.as_str())),
            MatchCfg::Variable {
                name,
                equals,
            } => Some(("variable", name.as_str(), equals.as_str())),
            MatchCfg::ClaimContains {
                name,
                value,
            } => {
                let entries = members.entry(name.as_str()).or_default();
                entries.insert(value.as_str());
                if entries.len() > 64 {
                    return false;
                }
                None
            }
            _ => None,
        };
        if let Some((kind, name, value)) = pair {
            if equal
                .insert((kind, name), value)
                .is_some_and(|old| old != value)
            {
                return false;
            }
        }
    }
    !members
        .keys()
        .any(|name| equal.contains_key(&("claim", *name)))
}

/// 业务作用：在同一个选择时刻比较认证与风险枚举，证明两个兄弟条件互斥，不跨策略阶段错误合并。
///
/// 参数说明：
/// - `left`：共享同一个父层已经产生的冻结上下文。
/// - `right`：共享同一个父层已经产生的冻结上下文。
///
/// 返回：认证布尔或风险枚举存在互斥取值时为 true。
fn exclusive_phase(left: &Node, right: &Node) -> bool {
    left.config.matches.iter().any(|left| {
        right
            .config
            .matches
            .iter()
            .any(|right| match (left, right) {
                (
                    MatchCfg::Authenticated {
                        value: left,
                    },
                    MatchCfg::Authenticated {
                        value: right,
                    },
                ) => left != right,
                (
                    MatchCfg::Risk {
                        equals: left,
                    },
                    MatchCfg::Risk {
                        equals: right,
                    },
                ) => left != right,
                _ => false,
            })
    })
}
