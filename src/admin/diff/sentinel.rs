//! 同代实际 Sentinel 规则的完整类型化比较，不输出规则正文。

use crate::config::model::{SentinelDegradeRuleCfg, SentinelFile, SentinelFlowRuleCfg};
use std::collections::{BTreeMap, HashMap};

#[derive(PartialEq, Eq)]
enum Rule<'a> {
    Flow(&'a SentinelFlowRuleCfg),
    Degrade(&'a SentinelDegradeRuleCfg),
}

#[derive(PartialEq, Eq)]
struct Entry<'a> {
    order: Option<usize>,
    rule: Rule<'a>,
}

/// 业务作用：借用实际规则建立稳定身份索引，并保留同一路由内的生效顺序。
///
/// 参数说明：
/// - `rules`：构建时已经验证唯一身份且归一缺省值的同代规则。
///
/// 返回：不复制规则或正文的索引，禁用规则仍可比较声明变化，但不占执行次序。
fn index(rules: &SentinelFile) -> BTreeMap<(bool, &str), Entry<'_>> {
    let mut index = BTreeMap::new();
    let mut orders = HashMap::<&str, usize>::new();
    for rule in &rules.flow {
        let order = rule.enabled.then(|| {
            let order = orders.entry(&rule.route).or_default();
            *order += 1;
            *order
        });
        index.insert(
            (false, rule.id.as_str()),
            Entry {
                order,
                rule: Rule::Flow(rule),
            },
        );
    }
    for rule in &rules.degrade {
        let order = rule.enabled.then(|| {
            let order = orders.entry(&rule.route).or_default();
            *order += 1;
            *order
        });
        index.insert(
            (true, rule.id.as_str()),
            Entry {
                order,
                rule: Rule::Degrade(rule),
            },
        );
    }
    index
}

/// 业务作用：比较全部规则字段与真实执行顺序，只向管理响应提供稳定业务标识。
///
/// 参数说明：
/// - `current`：活动快照中的实际 NAML 合并结果。
/// - `candidate`：完成完整构建的候选规则。
///
/// 返回：按类型和标识排序的新增、删除、变化列表，不包含原文、降级正文或环境求值结果。
pub(super) fn changes(
    current: &SentinelFile,
    candidate: &SentinelFile,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let current = index(current);
    let candidate = index(candidate);
    let added = candidate
        .keys()
        .filter(|key| !current.contains_key(*key))
        .map(label)
        .collect();
    let removed = current
        .keys()
        .filter(|key| !candidate.contains_key(*key))
        .map(label)
        .collect();
    let changed = current
        .iter()
        .filter_map(|(key, value)| {
            candidate
                .get(key)
                .filter(|next| *next != value)
                .map(|_| label(key))
        })
        .collect();
    (added, removed, changed)
}

/// 业务作用：将已验证且类型内唯一的规则身份编码为现有管理协议的标识。
///
/// 参数说明：
/// - `key`：规则类型和原始 id，不含正文。
///
/// 返回：flow 或 degrade 前缀加稳定 id；类型前缀不会与规则名互相覆盖。
fn label(key: &(bool, &str)) -> String {
    format!(
        "{}/{}",
        if key.0 {
            "degrade"
        } else {
            "flow"
        },
        key.1
    )
}
