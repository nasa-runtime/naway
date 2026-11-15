//! HTTP入口只合并当前已证明节点的原生累计与各自有效区间，不补齐未知节点。

use super::Node;
use crate::observability::ingress_protection::MAX_ENTRIES;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Rows<'a> {
    rows: BTreeMap<(&'a str, &'a str), Sum<'a>>,
}

#[derive(Default)]
struct Sum<'a> {
    nodes: Vec<&'a str>,
    valid: usize,
    observed: Option<[u64; 2]>,
    rate: [f64; 2],
}

#[derive(Serialize)]
pub(super) struct Row<'a> {
    listener: &'a str,
    workspace: &'a str,
    availability: &'static str,
    present_nodes: usize,
    valid_nodes: usize,
    unknown_nodes: usize,
    nodes: Vec<&'a str>,
    observed_rejections: Option<[String; 2]>,
    rejections_per_second: Option<[f64; 2]>,
}

impl<'a> Rows<'a> {
    /// 业务作用：合并完整目录和授权已通过的HTTP入口，保留工作区及原配置生命周期。
    ///
    /// 参数说明：
    /// - `node`：本轮已经通过身份、目录与年龄门的节点。
    /// - `workspace`：本域筛选，平台读取为None。
    /// - `search`：有界入口或工作区文字，不改变未知分母。
    ///
    /// 返回：全部匹配行已加入；唯一实体超预算时返回false，调用方撤下整页。
    pub(super) fn add(&mut self, node: &'a Node, workspace: Option<&str>, search: &str) -> bool {
        let Some(current) = node
            .sample
            .as_ref()
            .and_then(|sample| sample.ingress_protection.as_ref())
        else {
            return true;
        };
        let previous = node
            .previous
            .as_ref()
            .and_then(|sample| sample.ingress_protection.as_ref())
            .filter(|value| !value.capacity);
        for row in current
            .rows
            .iter()
            .filter(|row| workspace.is_none_or(|scope| row.workspace == scope))
        {
            if !search.is_empty()
                && ![&row.listener, &row.workspace]
                    .iter()
                    .any(|value| value.contains(search))
            {
                continue;
            }
            let key = (row.listener.as_str(), row.workspace.as_str());
            if self.rows.len() >= MAX_ENTRIES && !self.rows.contains_key(&key) {
                return false;
            }
            let value = self.rows.entry(key).or_default();
            value.observed = if value.nodes.is_empty() {
                Some(row.rejections)
            } else {
                value.observed.and_then(|old| {
                    Some([
                        old[0].checked_add(row.rejections[0])?,
                        old[1].checked_add(row.rejections[1])?,
                    ])
                })
            };
            value.nodes.push(&node.id);
            let old = previous
                .and_then(|previous| {
                    previous
                        .rows
                        .binary_search_by(|old| old.listener.cmp(&row.listener))
                        .ok()
                        .map(|index| &previous.rows[index])
                })
                .filter(|old| old.workspace == row.workspace);
            let Some((delta, elapsed)) = old
                .and_then(|old| {
                    Some([
                        row.rejections[0].checked_sub(old.rejections[0])?,
                        row.rejections[1].checked_sub(old.rejections[1])?,
                    ])
                })
                .zip(node.interval_ms)
                .filter(|(_, elapsed)| *elapsed > 0)
            else {
                continue;
            };
            value.valid += 1;
            for (rate, count) in value.rate.iter_mut().zip(delta) {
                *rate += count as f64 / (elapsed as f64 / 1000.0);
            }
        }
        true
    }

    /// 业务作用：交付同一轮入口实体及独立覆盖，累计以十进制文本避免浏览器宽整数舍入。
    ///
    /// 参数说明：
    /// - `unknown`：本范围无法证明当前目录的节点数。
    /// - `offset`：已验证的分页起点。
    /// - `limit`：最多交付的实体数量。
    ///
    /// 返回：匹配总数和有限页；溢出或区间缺席保持未知，部分和明确保留覆盖边界。
    pub(super) fn page(self, unknown: usize, offset: usize, limit: usize) -> (usize, Vec<Row<'a>>) {
        let total = self.rows.len();
        let rows = self
            .rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|((listener, workspace), value)| {
                let present = value.nodes.len();
                Row {
                    listener,
                    workspace,
                    availability: if unknown > 0
                        || value.observed.is_none()
                        || (value.valid > 0 && value.valid < present)
                    {
                        "partial"
                    } else if value.valid == 0 {
                        "sampling"
                    } else {
                        "available"
                    },
                    present_nodes: present,
                    valid_nodes: value.valid,
                    unknown_nodes: unknown,
                    nodes: value.nodes,
                    observed_rejections: value
                        .observed
                        .map(|counts| counts.map(|count| count.to_string())),
                    rejections_per_second: (value.valid > 0).then_some(value.rate),
                }
            })
            .collect();
        (total, rows)
    }
}
