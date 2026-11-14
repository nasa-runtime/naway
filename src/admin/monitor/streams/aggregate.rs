//! 监听器只合并各节点自己的同代相邻区间，未知成员不能贡献零流量。

use super::{model, Node};
use crate::admin::monitor::cluster::aggregate::Aggregate;
use crate::observability::http_stream::metrics::BOUNDS_MS;
use crate::observability::stream_traffic::{Reading, Totals, MAX_LISTENERS};
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
    totals: Option<Totals>,
    attempts: f64,
    admitted: f64,
    outcomes: [f64; 5],
    bytes: [f64; 2],
    datagrams: [f64; 2],
    dropped_datagrams: f64,
    latency: Aggregate,
}

#[derive(Serialize)]
pub(super) struct Row<'a> {
    listener: &'a str,
    protocol: &'a str,
    workspace: &'a str,
    availability: &'static str,
    present_nodes: usize,
    valid_nodes: usize,
    unknown_nodes: usize,
    nodes: Vec<&'a str>,
    active: Option<u64>,
    observed_totals: Option<Totals>,
    attempts_per_second: Option<f64>,
    admitted_per_second: Option<f64>,
    outcomes_per_second: Option<[f64; 5]>,
    bytes_per_second: Option<[f64; 2]>,
    datagrams_per_second: Option<[f64; 2]>,
    dropped_datagrams_per_second: Option<f64>,
    latency: serde_json::Value,
}

impl<'a> Rows<'a> {
    /// 业务作用：在完整目录与权限门成立后合并当前监听器，保留原生累计和有效相邻区间。
    ///
    /// 参数说明：
    /// - `node`：已经通过同代目录、年龄和授权复验的成员。
    /// - `workspace`：本域筛选，平台读取为 None。
    /// - `search`：有界文字筛选，不改变未知成员分母。
    ///
    /// 返回：所有匹配行已加入；唯一对象目录超出上限时返回 false，调用方撤下整页。
    pub(super) fn add(&mut self, node: &'a Node, workspace: Option<&str>, search: &str) -> bool {
        let Some(current) = node
            .sample
            .as_ref()
            .and_then(|sample| sample.stream_traffic.as_ref())
        else {
            return true;
        };
        let previous = node
            .previous
            .as_ref()
            .and_then(|sample| sample.stream_traffic.as_ref())
            .filter(|value| !value.capacity);
        for row in current
            .rows
            .iter()
            .filter(|row| workspace.is_none_or(|workspace| row.workspace == workspace))
        {
            if !search.is_empty()
                && ![&row.listener, &row.protocol, &row.workspace]
                    .into_iter()
                    .any(|value| value.contains(search))
            {
                continue;
            }
            let key = (
                row.listener.as_str(),
                row.protocol.as_str(),
                row.workspace.as_str(),
            );
            if self.rows.len() >= MAX_LISTENERS && !self.rows.contains_key(&key) {
                return false;
            }
            let value = self.rows.entry(key).or_default();
            value.active = if value.nodes.is_empty() {
                Some(row.totals.active)
            } else {
                value
                    .active
                    .and_then(|active| active.checked_add(row.totals.active))
            };
            value.totals = if value.nodes.is_empty() {
                Some(row.totals.clone())
            } else {
                value
                    .totals
                    .as_ref()
                    .and_then(|total| add(total, &row.totals))
            };
            value.nodes.push(&node.id);
            let old = previous
                .and_then(|snapshot| {
                    snapshot
                        .rows
                        .binary_search_by(|old| old.listener.cmp(&row.listener))
                        .ok()
                        .map(|index| &snapshot.rows[index])
                })
                .filter(|old| old.protocol == row.protocol && old.workspace == row.workspace);
            let Some((delta, elapsed)) = old
                .and_then(|old| subtract(row, old))
                .zip(node.interval_ms)
                .filter(|(_, elapsed)| *elapsed > 0)
            else {
                continue;
            };
            let seconds = elapsed as f64 / 1000.0;
            value.valid += 1;
            value.attempts += delta.attempts as f64 / seconds;
            value.admitted += delta.admitted as f64 / seconds;
            value.dropped_datagrams += delta.dropped_datagrams as f64 / seconds;
            for (sum, delta) in value.outcomes.iter_mut().zip(delta.outcomes) {
                *sum += delta as f64 / seconds;
            }
            for (sum, delta) in value.bytes.iter_mut().zip(delta.bytes) {
                *sum += delta as f64 / seconds;
            }
            for (sum, delta) in value.datagrams.iter_mut().zip(delta.datagrams) {
                *sum += delta as f64 / seconds;
            }
            let count = delta
                .buckets
                .iter()
                .try_fold(0u64, |sum, value| sum.checked_add(*value));
            let outcomes = delta
                .outcomes
                .iter()
                .try_fold(0u64, |sum, value| sum.checked_add(*value));
            if let Some(count) = count.filter(|count| Some(*count) == outcomes) {
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
                value.latency.add(&[], &latency, Some(elapsed));
            }
        }
        true
    }

    /// 业务作用：对同一轮监听器实体分页，累计仅代表当前已观察节点，不包含未知节点的推算。
    ///
    /// 参数说明：
    /// - `unknown`：无法证明当前对象分布的节点数，含目录覆盖缺口。
    /// - `offset`：当前分页起点。
    /// - `limit`：经校验的单页行数上限。
    ///
    /// 返回：匹配总数与有限页；溢出、区间缺席和未知成员保持明确的不完整状态。
    pub(super) fn page(self, unknown: usize, offset: usize, limit: usize) -> (usize, Vec<Row<'a>>) {
        let total = self.rows.len();
        let rows = self
            .rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|((listener, protocol, workspace), value)| {
                let present = value.nodes.len();
                Row {
                    listener,
                    protocol,
                    workspace,
                    availability: if unknown > 0
                        || value.active.is_none()
                        || value.totals.is_none()
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
                    active: value.active,
                    observed_totals: value.totals,
                    attempts_per_second: (value.valid > 0).then_some(value.attempts),
                    admitted_per_second: (value.valid > 0).then_some(value.admitted),
                    outcomes_per_second: (value.valid > 0).then_some(value.outcomes),
                    bytes_per_second: (value.valid > 0).then_some(value.bytes),
                    datagrams_per_second: (value.valid > 0).then_some(value.datagrams),
                    dropped_datagrams_per_second: (value.valid > 0)
                        .then_some(value.dropped_datagrams),
                    latency: value.latency.latency(present + unknown),
                }
            })
            .collect();
        (total, rows)
    }
}

/// 业务作用：对同协议、同归属的相邻累计求差，任一回退使本行区间未知。
///
/// 参数说明：
/// - `current`：本轮已经通过目录门的监听器事实。
/// - `previous`：进程与配置区间已经成立的前次同监听器事实。
///
/// 返回：所有累计都单调时的有限差值；回退不伪造零速率，瞬时在途仍单独展示。
fn subtract(current: &Reading, previous: &Reading) -> Option<Totals> {
    let (now, old) = (&current.totals, &previous.totals);
    Some(Totals {
        attempts: now.attempts.checked_sub(old.attempts)?,
        admitted: now.admitted.checked_sub(old.admitted)?,
        active: now.active,
        outcomes: subtract_array(&now.outcomes, &old.outcomes)?,
        bytes: subtract_array(&now.bytes, &old.bytes)?,
        datagrams: subtract_array(&now.datagrams, &old.datagrams)?,
        dropped_datagrams: now.dropped_datagrams.checked_sub(old.dropped_datagrams)?,
        duration_micros: now.duration_micros.checked_sub(old.duration_micros)?,
        buckets: subtract_array(&now.buckets, &old.buckets)?,
    })
}

/// 业务作用：累计已观察节点当前持有的原生值，溢出不能被饱和值冒充完整事实。
///
/// 参数说明：
/// - `first`：已合并的当前观察总数。
/// - `second`：本节点当前累计，仍只属于自己的配置生命周期。
///
/// 返回：每个字段都可精确相加时的观察和；任一溢出返回 None。
fn add(first: &Totals, second: &Totals) -> Option<Totals> {
    Some(Totals {
        attempts: first.attempts.checked_add(second.attempts)?,
        admitted: first.admitted.checked_add(second.admitted)?,
        active: first.active.checked_add(second.active)?,
        outcomes: add_array(&first.outcomes, &second.outcomes)?,
        bytes: add_array(&first.bytes, &second.bytes)?,
        datagrams: add_array(&first.datagrams, &second.datagrams)?,
        dropped_datagrams: first
            .dropped_datagrams
            .checked_add(second.dropped_datagrams)?,
        duration_micros: first.duration_micros.checked_add(second.duration_micros)?,
        buckets: add_array(&first.buckets, &second.buckets)?,
    })
}

/// 业务作用：在固定栈数组中验证同类累计的单调性，不建立动态指标字典。
///
/// 参数说明：
/// - `current`：当前固定维度累计。
/// - `previous`：前次相同维度累计。
///
/// 返回：每个元素均未回退时的差值；任一回退返回 None。
fn subtract_array<const N: usize>(current: &[u64; N], previous: &[u64; N]) -> Option<[u64; N]> {
    let mut values = [0; N];
    for index in 0..N {
        values[index] = current[index].checked_sub(previous[index])?;
    }
    Some(values)
}

/// 业务作用：以固定栈数组保留精确观察和，溢出不污染其它区间或节点。
///
/// 参数说明：
/// - `first`：已经合并的相同维度累计。
/// - `second`：本节点固定维度累计。
///
/// 返回：全部元素均可精确相加时的数组；任一溢出返回 None。
fn add_array<const N: usize>(first: &[u64; N], second: &[u64; N]) -> Option<[u64; N]> {
    let mut values = [0; N];
    for index in 0..N {
        values[index] = first[index].checked_add(second[index])?;
    }
    Some(values)
}
