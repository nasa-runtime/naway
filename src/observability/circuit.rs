//! 熔断执行状态的固定观测，不枚举规则身份或读取共享后端。

use super::metrics::ShardedCounter;
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const NAMES: [&str; 3] = ["closed", "open", "half_open"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

#[derive(Default)]
pub(crate) struct Counters {
    states: [AtomicU64; 3],
    active: AtomicU64,
    transitions: [ShardedCounter; 6],
}

pub(crate) static DESCRIPTORS: [MetricDescriptor; 3] = [
    MetricDescriptor {
        name: "gw_circuit_state_instances",
        help: "Retained node-local circuit execution states, including prior policies still awaiting safe reclamation; not unique cluster rules.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &["state"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_circuit_active_calls",
        help: "Active node-local circuit permits; shared statistics do not imply a shared half-open authority.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_circuit_transitions_total",
        help: "Actual node-local circuit state transitions; cancelling a half-open permit returns to open.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["from", "to"],
        histogram_bounds: &[],
    },
];

/// 状态对象的唯一观察凭证；只保留固定统计owner，不保存规则键或请求身份。
pub(crate) struct Observation {
    counters: Arc<Counters>,
    state: State,
    active: usize,
}

impl std::fmt::Debug for Observation {
    /// 业务作用：仅暴露固定状态及本实例活动数，不展开整个进程统计owner。
    ///
    /// 参数说明：
    /// - `formatter`：调用方的诊断输出。
    ///
    /// 返回：有限结构化描述，不包含规则或租户标识。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Observation")
            .field("state", &self.state)
            .field("active", &self.active)
            .finish()
    }
}

impl Observation {
    /// 业务作用：把新建的关闭态执行实例纳入进程观察，回收责任绑定原状态对象。
    ///
    /// 参数说明：
    /// - `counters`：当前进程共享的固定事实源。
    ///
    /// 返回：唯一观察凭证，不修改熔断权威或配置。
    pub(crate) fn new(counters: Arc<Counters>) -> Self {
        counters.states[State::Closed as usize].fetch_add(1, Ordering::Relaxed);
        Self {
            counters,
            state: State::Closed,
            active: 0,
        }
    }

    /// 业务作用：在原状态锁内映射已发生的执行迁移及许可变化，采样无需扫描热状态表。
    ///
    /// 参数说明：
    /// - `state`：状态机完成本步更新后的真实保护态。
    /// - `active`：同一实例仍持有的许可数。
    ///
    /// 返回：同步固定计数；相同状态不会新增迁移，观察不能触发探测或开放路由。
    pub(crate) fn update(&mut self, state: State, active: usize) {
        if self.state != state {
            let from = self.state as usize;
            let to = state as usize;
            self.counters.states[from].fetch_sub(1, Ordering::Relaxed);
            self.counters.states[to].fetch_add(1, Ordering::Relaxed);
            self.counters.transitions[from * 2 + to - usize::from(to > from)].add(1);
            self.state = state;
        }
        if active > self.active {
            self.counters
                .active
                .fetch_add((active - self.active) as u64, Ordering::Relaxed);
        } else if active < self.active {
            self.counters
                .active
                .fetch_sub((self.active - active) as u64, Ordering::Relaxed);
        }
        self.active = active;
    }
}

impl Drop for Observation {
    /// 业务作用：随真实执行状态撤下其观察数量，退休配置不会永久留下假活跃状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还本实例最后的状态和许可计数；不伪造恢复或其它状态迁移。
    fn drop(&mut self) {
        self.counters.states[self.state as usize].fetch_sub(1, Ordering::Relaxed);
        self.counters
            .active
            .fetch_sub(self.active as u64, Ordering::Relaxed);
    }
}

impl Counters {
    /// 业务作用：读取十项固定熔断事实，各出口不维护重复状态表。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前本地状态实例/活动许可和累计迁移；并发读取允许瞬时弱一致。
    pub(crate) fn samples(&self) -> Vec<MetricSample> {
        let mut samples = Vec::with_capacity(10);
        for (state, value) in NAMES.into_iter().zip(&self.states) {
            samples.push(MetricSample {
                name: DESCRIPTORS[0].name,
                labels: vec![("state", state.into())],
                value: MetricValue::Gauge(value.load(Ordering::Relaxed) as f64),
            });
        }
        samples.push(MetricSample {
            name: DESCRIPTORS[1].name,
            labels: vec![],
            value: MetricValue::Gauge(self.active.load(Ordering::Relaxed) as f64),
        });
        for (from, source) in NAMES.iter().enumerate() {
            for (to, target) in NAMES.iter().enumerate() {
                if from == to {
                    continue;
                }
                samples.push(MetricSample {
                    name: DESCRIPTORS[2].name,
                    labels: vec![("from", (*source).into()), ("to", (*target).into())],
                    value: MetricValue::Counter(
                        self.transitions[from * 2 + to - usize::from(to > from)].load(),
                    ),
                });
            }
        }
        samples
    }

    /// 业务作用：由统一描述符输出当前熔断计数，保持文本和结构化出口一致。
    ///
    /// 参数说明：
    /// - `output`：已有Prometheus响应缓冲。
    ///
    /// 返回：追加固定系列，不扫描规则、请求或远端Redis。
    pub(crate) fn render(&self, output: &mut String) {
        nametrics_core::atomic::render_snapshot(
            &DESCRIPTORS.iter().collect::<Vec<_>>(),
            &self.samples(),
            output,
        );
    }
}
