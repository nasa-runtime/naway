//! 路由聚合使用各节点自己的相邻区间，缺席与回退不会贡献假零或旧流量。

use super::{model, Node};
use crate::admin::monitor::cluster::aggregate::Aggregate;
use crate::observability::http_stream::{
    metrics::BOUNDS_MS,
    routes::{Reading, Totals, MAX_ROUTES},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Rows<'a> {
    rows: BTreeMap<(&'a str, &'a str, &'a str), Sum<'a>>,
}

#[derive(Default)]
struct Sum<'a> {
    nodes: Vec<&'a str>,
    valid: usize,
    active: Option<u64>,
    requests: f64,
    responses: [f64; 5],
    bytes: f64,
    outcomes: [f64; 4],
    latency: Aggregate,
}

#[derive(Serialize)]
pub(super) struct Row<'a> {
    proxy: &'a str,
    route: &'a str,
    workspace: &'a str,
    availability: &'static str,
    present_nodes: usize,
    valid_nodes: usize,
    unknown_nodes: usize,
    nodes: Vec<&'a str>,
    active: Option<u64>,
    requests_per_second: Option<f64>,
    responses_per_second: Option<[f64; 5]>,
    response_bytes_per_second: Option<f64>,
    outcomes_per_second: Option<[f64; 4]>,
    latency: serde_json::Value,
}

impl<'a> Rows<'a> {
    /// 业务作用：只把已经通过成员与工作区门的节点路由并入有限目录，原始身份通过借用共享。
    ///
    /// 参数说明：
    /// - `node`：已复验当前有效性的节点。
    /// - `workspace`：本域筛选，None代表有权读取的平台目录。
    /// - `search`：有限文字搜索，不改变覆盖分母。
    ///
    /// 返回：全部符合条件的行加入；超过聚合目录上限返回false，调用方丢弃本轮结果。
    pub(super) fn add(&mut self, node: &'a Node, workspace: Option<&str>, search: &str) -> bool {
        let Some(sample) = &node.sample else {
            return true;
        };
        let Some(current) = &sample.route_traffic else {
            return true;
        };
        let previous = node
            .previous
            .as_ref()
            .and_then(|sample| sample.route_traffic.as_ref())
            .filter(|value| !value.capacity);
        for row in current
            .rows
            .iter()
            .filter(|row| workspace.is_none_or(|workspace| row.workspace == workspace))
        {
            if !search.is_empty()
                && ![&row.proxy, &row.route, &row.workspace]
                    .into_iter()
                    .any(|value| value.contains(search))
            {
                continue;
            }
            let key = (
                row.proxy.as_str(),
                row.route.as_str(),
                row.workspace.as_str(),
            );
            if self.rows.len() >= MAX_ROUTES && !self.rows.contains_key(&key) {
                return false;
            }
            let sum = self.rows.entry(key).or_default();
            sum.active = if sum.nodes.is_empty() {
                Some(row.totals.active)
            } else {
                sum.active
                    .and_then(|active| active.checked_add(row.totals.active))
            };
            sum.nodes.push(&node.id);
            let old = previous
                .and_then(|value| {
                    value
                        .rows
                        .binary_search_by(|old| {
                            (&old.proxy, &old.route).cmp(&(&row.proxy, &row.route))
                        })
                        .ok()
                        .map(|index| &value.rows[index])
                })
                .filter(|old| old.workspace == row.workspace);
            if let Some((delta, elapsed)) = old
                .and_then(|old| delta(row, old))
                .zip(node.interval_ms)
                .filter(|(_, elapsed)| *elapsed > 0)
            {
                let seconds = elapsed as f64 / 1000.0;
                sum.valid += 1;
                sum.requests += delta.requests as f64 / seconds;
                sum.bytes += delta.bytes as f64 / seconds;
                for (sum, value) in sum.responses.iter_mut().zip(delta.responses) {
                    *sum += value as f64 / seconds;
                }
                for (sum, value) in sum.outcomes.iter_mut().zip(delta.outcomes) {
                    *sum += value as f64 / seconds;
                }
                let count = delta
                    .buckets
                    .iter()
                    .try_fold(0u64, |sum, value| sum.checked_add(*value));
                if let Some(count) = count {
                    let latency = model::Latency {
                        availability: "available",
                        count: Some(count),
                        mean_ms: (count > 0)
                            .then(|| delta.duration_micros as f64 / count as f64 / 1000.0),
                        p50_ms: None,
                        p95_ms: None,
                        p99_ms: None,
                        bounds_ms: BOUNDS_MS.to_vec(),
                        buckets: Some(delta.buckets.to_vec()),
                    };
                    sum.latency.add(&[], &latency, Some(elapsed));
                }
            }
        }
        true
    }

    /// 业务作用：按稳定对象身份分页输出同一观察轮次，未知节点仍影响每行覆盖结论。
    ///
    /// 参数说明：
    /// - `unknown`：本范围内无法证明当前对象目录的节点数。
    /// - `offset`：经校验的分页起点。
    /// - `limit`：单页最多行数。
    ///
    /// 返回：匹配总数和有限页；数值只由实际观测节点贡献，不补齐失联值。
    pub(super) fn page(self, unknown: usize, offset: usize, limit: usize) -> (usize, Vec<Row<'a>>) {
        let total = self.rows.len();
        let rows = self
            .rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|((proxy, route, workspace), value)| {
                let present = value.nodes.len();
                Row {
                    proxy,
                    route,
                    workspace,
                    availability: if value.valid == 0 {
                        "sampling"
                    } else if unknown > 0 || value.valid < present || value.active.is_none() {
                        "partial"
                    } else {
                        "available"
                    },
                    present_nodes: present,
                    valid_nodes: value.valid,
                    unknown_nodes: unknown,
                    nodes: value.nodes,
                    active: value.active,
                    requests_per_second: (value.valid > 0).then_some(value.requests),
                    responses_per_second: (value.valid > 0).then_some(value.responses),
                    response_bytes_per_second: (value.valid > 0).then_some(value.bytes),
                    outcomes_per_second: (value.valid > 0).then_some(value.outcomes),
                    latency: value.latency.latency(present + unknown),
                }
            })
            .collect();
        (total, rows)
    }
}

/// 业务作用：对同一归属的相邻路由事实求差，任一累计值回退都不伪造负速率或有效零。
///
/// 参数说明：
/// - `current`：当前配置代的事实。
/// - `previous`：已通过进程、配置与采样区间门的前次事实。
///
/// 返回：所有累计字段单调时的差值；否则该行本区间未知，瞬时在途量仍独立可见。
fn delta(current: &Reading, previous: &Reading) -> Option<Totals> {
    let (now, old) = (&current.totals, &previous.totals);
    Some(Totals {
        requests: now.requests.checked_sub(old.requests)?,
        active: now.active,
        responses: subtract(&now.responses, &old.responses)?,
        bytes: now.bytes.checked_sub(old.bytes)?,
        outcomes: subtract(&now.outcomes, &old.outcomes)?,
        duration_micros: now.duration_micros.checked_sub(old.duration_micros)?,
        buckets: subtract(&now.buckets, &old.buckets)?,
    })
}

/// 业务作用：以固定栈数组验证各互斥类别的单调性，不分配临时指标目录。
///
/// 参数说明：
/// - `current`：同一固定目录的当前累计。
/// - `previous`：前次成功累计。
///
/// 返回：所有元素均未回退时的差值数组，任一回退返回None。
fn subtract<const N: usize>(current: &[u64; N], previous: &[u64; N]) -> Option<[u64; N]> {
    let mut result = [0; N];
    for index in 0..N {
        result[index] = current[index].checked_sub(previous[index])?;
    }
    Some(result)
}
